using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Tests;

public sealed class PushedAuthorizationIntegrationTests
{
    private const string Callback = "http://localhost:4321/callback";
    private static string Csrf(string html) => Regex.Match(html,
        "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    private static async Task Register(ParFactory factory, string consent = ConsentTypes.Implicit,
        bool permission = true, bool required = false, bool confidential = false, string id = "par-client")
    {
        using var scope = factory.Services.CreateScope();
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = id, ClientType = confidential ? ClientTypes.Confidential : ClientTypes.Public,
            ClientSecret = confidential ? "par-test-secret" : null, ConsentType = consent,
            RedirectUris = { new Uri(Callback) },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email, Permissions.Scopes.Profile }
        };
        if (permission) descriptor.Permissions.Add(Permissions.Endpoints.PushedAuthorization);
        if (required) descriptor.Requirements.Add(Requirements.Features.PushedAuthorizationRequests);
        await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(descriptor);
    }

    private static HttpClient Browser(ParFactory factory) => factory.CreateClient(new WebApplicationFactoryClientOptions
        { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });

    private static async Task Login(HttpClient browser, bool admin = false)
    {
        var csrf = Csrf(await browser.GetStringAsync("/Account/Login"));
        using var response = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = admin ? CustomWebApplicationFactory.AdminEmail : CustomWebApplicationFactory.TestUserEmail,
            ["Password"] = admin ? CustomWebApplicationFactory.AdminPassword : CustomWebApplicationFactory.TestUserPassword,
            ["__RequestVerificationToken"] = csrf
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    private static Dictionary<string, string> Parameters(string verifier) => new()
    {
        ["client_id"] = "par-client", ["redirect_uri"] = Callback, ["response_type"] = "code",
        ["scope"] = "openid email profile", ["state"] = "par-state",
        ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
        ["code_challenge_method"] = "S256"
    };

    [Theory]
    [InlineData("other-user")]
    [InlineData("implicit")]
    [InlineData("allow")]
    [InlineData("deny")]
    public async Task PushedRequest_TraversesLoginAndConsentWithoutBrowserParameterCopies(string decision)
    {
        using var factory = new ParFactory();
        using var browser = Browser(factory);
        await Register(factory, decision == "implicit" ? ConsentTypes.Implicit : ConsentTypes.Explicit);
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        using var pushed = await browser.PostAsync("/connect/par", new FormUrlEncodedContent(Parameters(verifier)));
        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);
        using var pushPayload = JsonDocument.Parse(await pushed.Content.ReadAsStringAsync());
        Assert.InRange(pushPayload.RootElement.GetProperty("expires_in").GetInt32(), 89, 90);
        var requestUri = pushPayload.RootElement.GetProperty("request_uri").GetString()!;
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
            { ["client_id"] = "par-client", ["request_uri"] = requestUri });
        using var anonymous = await browser.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        Assert.Contains("/Account/Login", anonymous.Headers.Location!.OriginalString);
        await Login(browser);
        using var authorized = await browser.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, authorized.StatusCode);
        var location = authorized.Headers.Location!;
        if (decision != "implicit")
        {
            Assert.StartsWith("/Consent?", location.OriginalString);
            Assert.DoesNotContain("scope=", location.OriginalString);
            Assert.DoesNotContain("redirect_uri=", location.OriginalString);
            var html = await browser.GetStringAsync(location);
            Assert.Contains("email", html);
            if (decision == "other-user")
            {
                var sessionPage = await browser.GetStringAsync("/Session");
                using var logout = await browser.PostAsync("/Account/Logout", new FormUrlEncodedContent(
                    new Dictionary<string, string> { ["__RequestVerificationToken"] = Csrf(sessionPage) }));
                Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
                await Login(browser, admin: true);
                using var stolen = await browser.GetAsync(location);
                Assert.Equal(HttpStatusCode.BadRequest, stolen.StatusCode);
                return;
            }
            var returnUrl = QueryHelpers.ParseQuery(new Uri("https://localhost" + location).Query)["returnUrl"].ToString();
            using var consent = await browser.PostAsync("/Consent", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["ReturnUrl"] = returnUrl, ["Decision"] = decision, ["ScopesConsented"] = "profile",
                ["RememberConsent"] = "false", ["__RequestVerificationToken"] = Csrf(html)
            }));
            Assert.Equal(HttpStatusCode.Redirect, consent.StatusCode);
            using var completion = await browser.GetAsync(consent.Headers.Location);
            Assert.Equal(HttpStatusCode.Redirect, completion.StatusCode);
            location = completion.Headers.Location!;
        }
        Assert.StartsWith(Callback, location.OriginalString);
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("par-state", query["state"]);
        if (decision == "deny")
        {
            Assert.Equal("access_denied", query["error"]);
            Assert.False(query.ContainsKey("code"));
            return;
        }
        using var exchange = await browser.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = "par-client",
            ["redirect_uri"] = Callback, ["code_verifier"] = verifier, ["code"] = query["code"].ToString()
        }));
        Assert.True(exchange.IsSuccessStatusCode, await exchange.Content.ReadAsStringAsync());
        using var token = JsonDocument.Parse(await exchange.Content.ReadAsStringAsync());
        var jwt = new JsonWebToken(token.RootElement.GetProperty("access_token").GetString()!);
        Assert.Equal(decision == "implicit", jwt.TryGetClaim("email", out _));
        using var replay = await browser.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Theory]
    [InlineData("disabled-dcr")]
    [InlineData("permission")]
    [InlineData("redirect")]
    [InlineData("pkce")]
    [InlineData("secret")]
    public async Task InvalidPush_IsRejectedBeforeCreatingRequestUri(string defect)
    {
        using var factory = new ParFactory();
        using var browser = Browser(factory);
        await Register(factory, permission: defect != "permission", confidential: defect == "secret");
        if (defect == "disabled-dcr")
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            db.DynamicClientRegistrations.Add(new DynamicClientRegistration { ClientId = "par-client", IsDisabled = true });
            await db.SaveChangesAsync();
        }
        var parameters = Parameters(Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)));
        if (defect == "redirect") parameters["redirect_uri"] = "https://unregistered.invalid/callback";
        if (defect == "pkce") parameters.Remove("code_challenge");
        if (defect == "secret") parameters["client_secret"] = "wrong";
        using var response = await browser.PostAsync("/connect/par", new FormUrlEncodedContent(parameters));
        Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.TryGetProperty("error", out _));
        Assert.False(json.RootElement.TryGetProperty("request_uri", out _));
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("other-client")]
    [InlineData("tampered")]
    public async Task RequestUri_IsBoundToClientAndLifetime(string defect)
    {
        using var factory = new ParFactory();
        using var browser = Browser(factory);
        await Register(factory);
        await Register(factory, id: "other-client");
        await Login(browser);
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        using var pushed = await browser.PostAsync("/connect/par", new FormUrlEncodedContent(Parameters(verifier)));
        using var json = JsonDocument.Parse(await pushed.Content.ReadAsStringAsync());
        var uri = json.RootElement.GetProperty("request_uri").GetString()!;
        if (defect == "expired") factory.Clock.Offset = TimeSpan.FromMinutes(20);
        if (defect == "tampered") uri += "tampered";
        using var response = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = defect == "other-client" ? "other-client" : "par-client", ["request_uri"] = uri
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RequiredClient_CannotBypassPar()
    {
        using var factory = new ParFactory();
        using var browser = Browser(factory);
        await Register(factory, required: true);
        using var response = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/authorize",
            Parameters(Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32))!).ToDictionary(p => p.Key, p => (string?)p.Value)));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DiscoveryAndEndpoint_FollowFeatureToggle(bool enabled)
    {
        using var factory = new ParFactory(enabled);
        using var browser = Browser(factory);
        using var json = JsonDocument.Parse(await browser.GetStringAsync("/.well-known/openid-configuration"));
        Assert.Equal(enabled, json.RootElement.TryGetProperty("pushed_authorization_request_endpoint", out _));
        if (!enabled)
        {
            using var response = await browser.PostAsync("/connect/par", new FormUrlEncodedContent(Parameters("test")));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    private sealed class TestClock : TimeProvider
    {
        public TimeSpan Offset { get; set; }
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

    private sealed class ParFactory : CustomWebApplicationFactory
    {
        private readonly string? prior = Environment.GetEnvironmentVariable("OpenIddict__AdvancedFlows__PAR__Enabled");
        public TestClock Clock { get; } = new();
        public ParFactory(bool enabled = true) => Environment.SetEnvironmentVariable(
            "OpenIddict__AdvancedFlows__PAR__Enabled", enabled ? "true" : "false");
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services => services.PostConfigure<OpenIddictServerOptions>(options => options.TimeProvider = Clock));
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) Environment.SetEnvironmentVariable("OpenIddict__AdvancedFlows__PAR__Enabled", prior);
        }
    }
}
