using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Hosting;
using Andy.Auth.Server.Services.Revocation;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests;

public sealed class LiveAdminApiIntegrationTests
{
    private static string Csrf(string html) => Regex.Match(html,
        "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    [Theory]
    [InlineData("token")]
    [InlineData("other-replica-token")]
    [InlineData("authorization")]
    [InlineData("single")]
    [InlineData("all")]
    [InlineData("disabled")]
    [InlineData("role")]
    [InlineData("locked")]
    [InlineData("deleted")]
    [InlineData("expired")]
    [InlineData("inactive")]
    [InlineData("missing")]
    [InlineData("other-user")]
    [InlineData("logout")]
    [InlineData("oidc-logout")]
    [InlineData("unavailable")]
    public async Task IssuedAdminToken_ReconcilesAuthorityOnEveryPrivilegedRequest(string mutation)
    {
        using var factory = new CaptureFactory();
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        using var api = factory.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false });
        var csrf = Csrf(await browser.GetStringAsync("/Account/Login"));
        using var login = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = CustomWebApplicationFactory.AdminEmail,
            ["Password"] = CustomWebApplicationFactory.AdminPassword,
            ["__RequestVerificationToken"] = csrf
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        const string callback = "http://localhost:4200/auth/callback";
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        using var authorize = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "andy-docs-web", ["redirect_uri"] = callback,
            ["response_type"] = "code", ["scope"] = "openid roles",
            ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
            ["code_challenge_method"] = "S256"
        }));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var code = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"].ToString();
        using var exchange = await browser.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = "andy-docs-web",
            ["redirect_uri"] = callback, ["code_verifier"] = verifier, ["code"] = code
        }));
        Assert.True(exchange.IsSuccessStatusCode, await exchange.Content.ReadAsStringAsync());
        using var payload = JsonDocument.Parse(await exchange.Content.ReadAsStringAsync());
        var accessToken = payload.RootElement.GetProperty("access_token").GetString()!;
        var token = new JsonWebToken(accessToken);
        var sessionId = token.GetPayloadValue<string>(AndyAuthSignInManager.SessionIdClaimType);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var before = await api.GetAsync("/api/users");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var resource = await LiveConsumerFixture.StartAsync(factory, token);
        using var consumer = resource.GetTestClient();
        consumer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var consumerBefore = await consumer.GetAsync("/sensitive");
        Assert.Equal(HttpStatusCode.OK, consumerBefore.StatusCode);

        if (mutation == "logout")
        {
            var page = await browser.GetStringAsync("/Session");
            using var logout = await browser.PostAsync("/Account/Logout", new FormUrlEncodedContent(
                new Dictionary<string, string> { ["__RequestVerificationToken"] = Csrf(page) }));
            Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        }
        else if (mutation == "oidc-logout")
        {
            using var logout = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/logout", new Dictionary<string, string?>
            {
                ["id_token_hint"] = payload.RootElement.GetProperty("id_token").GetString(),
                ["post_logout_redirect_uri"] = "http://localhost:4200/"
            }));
            Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        }
        else
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByIdAsync(token.Subject))!;
            var session = await db.UserSessions.SingleAsync(s => s.SessionId == sessionId);
            switch (mutation)
            {
                case "token":
                    var tokens = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictTokenManager>();
                    var storedToken = await tokens.FindByIdAsync(token.GetClaim(OpenIddictConstants.Claims.Private.TokenId).Value);
                    Assert.NotNull(storedToken);
                    Assert.True(await tokens.TryRevokeAsync(storedToken));
                    break;
                case "other-replica-token":
                    // A store update on another replica does not invalidate this
                    // process's OpenIddict entity cache. The policy must read fresh.
                    var storedId = token.GetClaim(OpenIddictConstants.Claims.Private.TokenId).Value;
                    Assert.Equal(1, await db.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken>()
                        .Where(entry => entry.Id == storedId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(entry => entry.Status, "revoked")));
                    break;
                case "authorization":
                    var manager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictAuthorizationManager>();
                    await foreach (var authorization in manager.FindAsync(subject: user.Id, client: null, status: null, type: null, scopes: null))
                        Assert.True(await manager.TryRevokeAsync(authorization));
                    break;
                case "single":
                    // Another active session cannot rescue the revoked token's session.
                    await scope.ServiceProvider.GetRequiredService<SessionService>().CreateSessionAsync(
                        user.Id, Guid.NewGuid().ToString("N"), "127.0.0.1", "Other browser");
                    session.IsRevoked = true; break;
                case "all":
                    await scope.ServiceProvider.GetRequiredService<SessionService>().RevokeAllSessionsAsync(user.Id, "test"); break;
                case "disabled": user.IsActive = false; break;
                case "role": Assert.True((await users.RemoveFromRoleAsync(user, "Admin")).Succeeded); break;
                case "locked": user.LockoutEnabled = true; user.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1); break;
                case "deleted": user.DeletedAt = DateTime.UtcNow; break;
                case "expired": session.ExpiresAt = DateTime.UtcNow.AddSeconds(-1); break;
                case "inactive": session.LastActivity = DateTime.UtcNow.AddDays(-30); break;
                case "missing": db.UserSessions.Remove(session); break;
                case "other-user": session.UserId = (await users.FindByEmailAsync(CustomWebApplicationFactory.TestUserEmail))!.Id; break;
                case "unavailable": await db.Database.ExecuteSqlRawAsync("DROP TABLE UserSessions"); break;
            }
            await db.SaveChangesAsync();
        }

        using var consumerAfter = await consumer.GetAsync("/sensitive");
        Assert.Equal(mutation == "unavailable" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Unauthorized,
            consumerAfter.StatusCode);

        Assert.True(token.ValidTo > DateTime.UtcNow, "The original token must still be unexpired.");
        foreach (var path in new[] { "/api/users", "/api/groups", "/mcp/tools/users/list", "/mcp" })
        {
            using var after = await api.GetAsync(path);
            Assert.Equal(mutation == "unavailable" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Forbidden,
                after.StatusCode);
            Assert.True(after.Headers.CacheControl?.NoStore);
            if (mutation == "unavailable") Assert.Equal(TimeSpan.FromSeconds(5), after.Headers.RetryAfter?.Delta);
        }
        if (mutation is "single" or "all" or "disabled" or "deleted" or "missing" or "logout" or "oidc-logout")
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            Assert.True(await db.RevocationOutbox.AsNoTracking().AnyAsync(message => message.SessionId == sessionId && message.Recipient == "test-resource"));
        }
    }

    private sealed class CaptureFactory : CustomWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            // Enable transactional capture through options. The environment flag
            // stays off, so no outbound background worker is registered here.
            // Dispatcher/receiver integration is tested separately with real HTTP.
            builder.ConfigureTestServices(services => services.Configure<RevocationDeliveryOptions>(options =>
            {
                options.Enabled = true;
                options.Targets = new() { new() { Audience = "test-resource", Endpoint = "https://receiver.invalid/auth/events" } };
            }));
        }
    }
}
