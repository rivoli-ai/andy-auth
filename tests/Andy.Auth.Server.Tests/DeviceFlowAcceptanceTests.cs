using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using OpenIddict.Server;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Tests;

public sealed class DeviceFlowAcceptanceTests
{
    private static string Csrf(string html) => Regex.Match(html,
        "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    [Theory]
    [InlineData("expired")]
    [InlineData("allow")]
    [InlineData("deny")]
    [InlineData("invalid-decision")]
    [InlineData("csrf")]
    [InlineData("revoked-session")]
    public async Task BrowserApprovalAndCliPolling_EnforceDecisionAndSession(string decision)
    {
        using var factory = new DeviceFactory();
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        using var cli = factory.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false });
        using (var scope = factory.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "device-acceptance", ClientType = ClientTypes.Public, ConsentType = ConsentTypes.Explicit,
                    Permissions = { Permissions.Endpoints.DeviceAuthorization, Permissions.Endpoints.Token,
                        Permissions.GrantTypes.DeviceCode, Permissions.GrantTypes.RefreshToken, Permissions.Scopes.Profile }
                });
        }
        var issuance = System.Diagnostics.Stopwatch.StartNew();
        using var start = await cli.PostAsync("/connect/device", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["client_id"] = "device-acceptance", ["scope"] = "openid profile offline_access" }));
        Assert.True(start.IsSuccessStatusCode, await start.Content.ReadAsStringAsync());
        using var json = JsonDocument.Parse(await start.Content.ReadAsStringAsync());
        var code = json.RootElement.GetProperty("device_code").GetString()!;
        var userCode = json.RootElement.GetProperty("user_code").GetString()!;
        Assert.InRange(json.RootElement.GetProperty("expires_in").GetInt32(),
            Math.Max(1, 600 - (int)Math.Ceiling(issuance.Elapsed.TotalSeconds) - 1), 600);
        var verify = QueryHelpers.AddQueryString("/connect/verify", "user_code", userCode);
        var poll = new Dictionary<string, string>
        {
            ["client_id"] = "device-acceptance", ["grant_type"] = GrantTypes.DeviceCode, ["device_code"] = code
        };
        using var pending = await cli.PostAsync("/connect/token", new FormUrlEncodedContent(poll));
        using var pendingJson = JsonDocument.Parse(await pending.Content.ReadAsStringAsync());
        Assert.Equal("authorization_pending", pendingJson.RootElement.GetProperty("error").GetString());
        if (decision == "expired")
        {
            factory.Clock.Offset = TimeSpan.FromMinutes(20);
            using var expired = await cli.PostAsync("/connect/token", new FormUrlEncodedContent(poll));
            using var expiredJson = JsonDocument.Parse(await expired.Content.ReadAsStringAsync());
            Assert.Equal(HttpStatusCode.BadRequest, expired.StatusCode);
            Assert.False(expiredJson.RootElement.TryGetProperty("access_token", out _));
            Assert.Equal("expired_token", expiredJson.RootElement.GetProperty("error").GetString());
            return;
        }
        using var anonymous = await browser.GetAsync(verify);
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        Assert.Contains("/Account/Login", anonymous.Headers.Location!.OriginalString);
        var csrf = Csrf(await browser.GetStringAsync("/Account/Login"));
        using var login = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = CustomWebApplicationFactory.TestUserEmail, ["Password"] = CustomWebApplicationFactory.TestUserPassword,
            ["__RequestVerificationToken"] = csrf
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var html = await browser.GetStringAsync(verify);
        // Reproduce the actual HTML form contract, not a synthetic alternate field name.
        var hidden = Regex.Match(html, "name=\"user_code\"[^>]*value=\"([^\"]+)\"");
        Assert.True(hidden.Success, "The verification form must submit OAuth's user_code parameter.");
        var form = new Dictionary<string, string>
        {
            ["user_code"] = WebUtility.HtmlDecode(hidden.Groups[1].Value),
            ["decision"] = decision is "deny" or "invalid-decision" ? decision : "allow",
            ["__RequestVerificationToken"] = decision == "csrf" ? "invalid" : Csrf(html)
        };
        using var approval = await browser.PostAsync("/connect/verify", new FormUrlEncodedContent(form));
        if (decision is "csrf" or "invalid-decision")
        {
            Assert.Equal(HttpStatusCode.BadRequest, approval.StatusCode);
            using var unchanged = await cli.PostAsync("/connect/token", new FormUrlEncodedContent(poll));
            using var unchangedJson = JsonDocument.Parse(await unchanged.Content.ReadAsStringAsync());
            Assert.Equal("authorization_pending", unchangedJson.RootElement.GetProperty("error").GetString());
            return;
        }
        if (decision == "deny")
        {
            Assert.Equal(HttpStatusCode.BadRequest, approval.StatusCode);
            Assert.Contains("access_denied", await approval.Content.ReadAsStringAsync());
        }
        else Assert.True(approval.IsSuccessStatusCode || approval.StatusCode == HttpStatusCode.Redirect,
            await approval.Content.ReadAsStringAsync());
        if (decision == "revoked-session")
        {
            using var scope = factory.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
            var user = (await users.FindByEmailAsync(CustomWebApplicationFactory.TestUserEmail))!;
            await scope.ServiceProvider.GetRequiredService<SessionService>().RevokeAllSessionsAsync(user.Id, "device test");
        }
        using var issued = await cli.PostAsync("/connect/token", new FormUrlEncodedContent(poll));
        using var issuedJson = JsonDocument.Parse(await issued.Content.ReadAsStringAsync());
        if (decision is "deny" or "revoked-session")
        {
            Assert.False(issued.IsSuccessStatusCode);
            Assert.False(issuedJson.RootElement.TryGetProperty("access_token", out _));
            Assert.Equal(decision == "deny" ? "access_denied" : "invalid_grant",
                issuedJson.RootElement.GetProperty("error").GetString());
            return;
        }
        Assert.True(issued.IsSuccessStatusCode, issuedJson.RootElement.ToString());
        var token = new JsonWebToken(issuedJson.RootElement.GetProperty("access_token").GetString()!);
        Assert.False(string.IsNullOrWhiteSpace(token.Subject));
        Assert.True(token.TryGetClaim(AndyAuthSignInManager.SessionIdClaimType, out _));
        Assert.True(issuedJson.RootElement.TryGetProperty("refresh_token", out _));
        using var replay = await cli.PostAsync("/connect/token", new FormUrlEncodedContent(poll));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }
    [Fact]
    public async Task DisabledDeviceFlow_IsNotAdvertisedOrAccepted()
    {
        using var factory = new DeviceFactory(false);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        using var discovery = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        Assert.False(discovery.RootElement.TryGetProperty("device_authorization_endpoint", out _));
        Assert.DoesNotContain(discovery.RootElement.GetProperty("grant_types_supported").EnumerateArray(),
            grant => grant.GetString() == GrantTypes.DeviceCode);
        using var response = await client.PostAsync("/connect/device", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["client_id"] = "device-acceptance" }));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private sealed class TestClock : TimeProvider
    {
        public TimeSpan Offset { get; set; }
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

    private sealed class DeviceFactory : CustomWebApplicationFactory
    {
        private readonly string? prior = Environment.GetEnvironmentVariable("OpenIddict__AdvancedFlows__DeviceFlow__Enabled");
        public TestClock Clock { get; } = new();
        public DeviceFactory(bool enabled = true) => Environment.SetEnvironmentVariable(
            "OpenIddict__AdvancedFlows__DeviceFlow__Enabled", enabled ? "true" : "false");
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services => services.PostConfigure<OpenIddictServerOptions>(options => options.TimeProvider = Clock));
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) Environment.SetEnvironmentVariable("OpenIddict__AdvancedFlows__DeviceFlow__Enabled", prior);
        }
    }

}
