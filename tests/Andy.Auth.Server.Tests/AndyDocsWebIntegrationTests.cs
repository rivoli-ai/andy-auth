using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests;

public sealed class AndyDocsWebIntegrationTests
{
    [Theory]
    [InlineData(4200)]
    [InlineData(4202)]
    public async Task LocalCallback_PkceIssuanceLogoutAndReseedingPreserveClient(int port)
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
        using (var scope = factory.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var client = (await manager.FindByClientIdAsync("andy-docs-web"))!;
            var originalId = await manager.GetIdAsync(client);
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
                { ClientId = "wagram-web", ClientType = "public" });
            var seeder = ActivatorUtilities.CreateInstance<DbSeeder>(scope.ServiceProvider);
            await seeder.SeedAsync();
            await seeder.SeedAsync();
            Assert.Null(await manager.FindByClientIdAsync("wagram-web"));
            Assert.Equal(originalId, await manager.GetIdAsync((await manager.FindByClientIdAsync("andy-docs-web"))!));
        }

        var loginHtml = await browser.GetStringAsync("/Account/Login");
        var csrf = Regex.Match(loginHtml, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(csrf.Success);
        using var login = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = CustomWebApplicationFactory.TestUserEmail,
            ["Password"] = CustomWebApplicationFactory.TestUserPassword,
            ["__RequestVerificationToken"] = csrf.Groups[1].Value
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var callback = $"http://localhost:{port}/auth/callback";
        var parameters = new Dictionary<string, string?>
        {
            ["client_id"] = "andy-docs-web", ["redirect_uri"] = callback,
            ["response_type"] = "code", ["scope"] = "openid", ["state"] = "docs-state"
        };
        using var noPkce = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", parameters));
        Assert.Equal(HttpStatusCode.BadRequest, noPkce.StatusCode);
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        parameters["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        parameters["code_challenge_method"] = "S256";
        using var authorize = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", parameters));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        Assert.StartsWith(callback, authorize.Headers.Location!.OriginalString);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location.Query);
        Assert.Equal("docs-state", query["state"].ToString());
        using var exchange = await browser.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = "andy-docs-web",
            ["redirect_uri"] = callback, ["code_verifier"] = verifier, ["code"] = query["code"].ToString()
        }));
        Assert.True(exchange.IsSuccessStatusCode, await exchange.Content.ReadAsStringAsync());
        using var payload = JsonDocument.Parse(await exchange.Content.ReadAsStringAsync());
        var idToken = payload.RootElement.GetProperty("id_token").GetString()!;
        var jwt = new JsonWebToken(idToken);
        Assert.Contains("andy-docs-web", jwt.Audiences);
        Assert.False(string.IsNullOrEmpty(jwt.Subject));
        using var logout = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/logout", new Dictionary<string, string?>
        {
            ["id_token_hint"] = idToken, ["post_logout_redirect_uri"] = $"http://localhost:{port}/"
        }));
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.Equal($"http://localhost:{port}/", logout.Headers.Location!.OriginalString);
    }
}
