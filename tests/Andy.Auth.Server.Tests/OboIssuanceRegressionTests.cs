using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// #118: use the real login and code/token endpoints. A hand-signed subject JWT
/// bypasses the manifest resource mapping that caused the production regression.
/// The actor uses the containers client contract; no M2M fallback is allowed.
/// This does not launch the containers proxy or the RBAC service.
/// </summary>
public sealed class OboIssuanceRegressionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LoginCodeIssuanceAndExchange_PreserveUserIdentity_AndRepairStaleResources(bool staleDatabase)
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        string userId;
        using (var services = factory.Services.CreateScope())
        {
            var db = services.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            userId = await db.Users.Where(u => u.Email == CustomWebApplicationFactory.TestUserEmail).Select(u => u.Id).SingleAsync();
            var scopes = services.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            if (staleDatabase)
            {
                var scope = (await scopes.FindByNameAsync("urn:andy-containers-api"))!;
                var descriptor = new OpenIddictScopeDescriptor();
                await scopes.PopulateAsync(descriptor, scope);
                descriptor.Resources.Remove("andy-containers-api");
                await scopes.UpdateAsync(scope, descriptor);
                Assert.DoesNotContain("andy-containers-api", await scopes.GetResourcesAsync(scope));
                await ActivatorUtilities.CreateInstance<DbSeeder>(services.ServiceProvider).SeedAsync();
            }
            var repaired = (await scopes.FindByNameAsync("urn:andy-containers-api"))!;
            Assert.Contains("andy-containers-api", await scopes.GetResourcesAsync(repaired));
        }

        var loginPage = await browser.GetStringAsync("/Account/Login");
        var csrf = Regex.Match(loginPage, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(csrf.Success);
        using var login = await browser.PostAsync("/Account/Login", Form(new()
        {
            ["Email"] = CustomWebApplicationFactory.TestUserEmail,
            ["Password"] = CustomWebApplicationFactory.TestUserPassword,
            ["__RequestVerificationToken"] = csrf.Groups[1].Value
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);

        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var state = Guid.NewGuid().ToString("N");
        const string redirectUri = "http://127.0.0.1/obo-callback";
        var authorizeUri = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "obo-regression-cli", ["redirect_uri"] = redirectUri,
            ["response_type"] = "code", ["scope"] = "openid urn:andy-containers-api",
            ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
            ["code_challenge_method"] = "S256", ["state"] = state
        });
        using var authorize = await browser.GetAsync(authorizeUri);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var location = authorize.Headers.Location!;
        Assert.StartsWith(redirectUri, location.OriginalString, StringComparison.Ordinal);
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(state, query["state"].ToString());
        Assert.False(query.ContainsKey("error"), location.OriginalString);
        Assert.False(string.IsNullOrEmpty(query["code"]));
        using var codeResponse = await browser.PostAsync("/connect/token", Form(new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = "obo-regression-cli",
            ["redirect_uri"] = redirectUri, ["code_verifier"] = verifier, ["code"] = query["code"].ToString()
        }));
        Assert.True(codeResponse.IsSuccessStatusCode, await codeResponse.Content.ReadAsStringAsync());
        using var codePayload = JsonDocument.Parse(await codeResponse.Content.ReadAsStringAsync());
        var subjectToken = codePayload.RootElement.GetProperty("access_token").GetString()!;
        var subject = new JsonWebToken(subjectToken);
        Assert.Equal(userId, subject.Subject);
        Assert.Contains("urn:andy-containers-api", subject.Audiences);
        Assert.Contains("andy-containers-api", subject.Audiences);
        var sessionId = subject.GetPayloadValue<string>(AndyAuthSignInManager.SessionIdClaimType);
        Assert.False(string.IsNullOrEmpty(sessionId));

        // A real OpenID Connect ID token is not an access-token subject, even
        // when submitted with subject_token_type=access_token.
        var idToken = codePayload.RootElement.GetProperty("id_token").GetString()!;
        using var idExchange = await browser.PostAsync("/connect/token", Exchange(idToken));
        Assert.False(idExchange.IsSuccessStatusCode);
        using var idError = JsonDocument.Parse(await idExchange.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", idError.RootElement.GetProperty("error").GetString());

        using var exchange = await browser.PostAsync("/connect/token", Exchange(subjectToken));
        Assert.True(exchange.IsSuccessStatusCode, await exchange.Content.ReadAsStringAsync());
        using var result = JsonDocument.Parse(await exchange.Content.ReadAsStringAsync());
        var exchangedToken = result.RootElement.GetProperty("access_token").GetString()!;

        // Verify using public discovery/JWKS just as an independent resource server
        // would, rather than trusting a decoded JWT or reaching for signing keys.
        using var discovery = JsonDocument.Parse(await browser.GetStringAsync("/.well-known/openid-configuration"));
        var jwksUri = new Uri(discovery.RootElement.GetProperty("jwks_uri").GetString()!);
        var jwks = new JsonWebKeySet(await browser.GetStringAsync(jwksUri.PathAndQuery));
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(exchangedToken, new TokenValidationParameters
        {
            ValidIssuer = discovery.RootElement.GetProperty("issuer").GetString(),
            ValidAudience = "urn:andy-models-api", IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidTypes = new[] { "at+jwt" }, ClockSkew = TimeSpan.Zero
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);
        var delegated = (JsonWebToken)validation.SecurityToken;
        Assert.Equal(userId, delegated.Subject); // RBAC external subject key, never email or actor client id.
        Assert.NotEqual(CustomWebApplicationFactory.TestUserEmail, delegated.Subject);
        Assert.Equal(new[] { "urn:andy-models-api" }, delegated.Audiences);
        Assert.Equal("andy-containers-api", delegated.GetPayloadValue<JsonElement>("act").GetProperty("sub").GetString());
        Assert.Equal(sessionId, delegated.GetPayloadValue<string>(AndyAuthSignInManager.SessionIdClaimType));
        Assert.Equal(subject.GetPayloadValue<string>(DeploymentTenant.ClaimType),
            delegated.GetPayloadValue<string>(DeploymentTenant.ClaimType));
        Assert.True(delegated.ValidTo <= subject.ValidTo);
        Assert.All(delegated.GetPayloadValue<string>("scope").Split(' '),
            scope => Assert.Contains(scope, subject.GetPayloadValue<string>("scope").Split(' ')));

        using (var services = factory.Services.CreateScope())
        {
            var sessions = services.ServiceProvider.GetRequiredService<SessionService>();
            Assert.True(await sessions.RevokeSessionByIdAsync(sessionId, "OBO regression revoked session"));
        }
        using var rejected = await browser.PostAsync("/connect/token", Exchange(subjectToken));
        Assert.False(rejected.IsSuccessStatusCode);
        using var error = JsonDocument.Parse(await rejected.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", error.RootElement.GetProperty("error").GetString());
    }

    private static FormUrlEncodedContent Form(Dictionary<string, string> fields) => new(fields);
    private static FormUrlEncodedContent Exchange(string token) => Form(new()
    {
        ["grant_type"] = TokenExchangeConstants.GrantType,
        ["client_id"] = CustomWebApplicationFactory.AndyContainersApiClientId,
        ["client_secret"] = "andy-containers-api-secret-change-in-production",
        ["subject_token"] = token,
        ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        ["resource"] = CustomWebApplicationFactory.AndyModelsApiAudience
    });
}
