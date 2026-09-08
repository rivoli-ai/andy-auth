using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Dpop;
using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Andy.Auth.Server.Services;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;
using Andy.Auth.Server.Services.Dpop;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Andy.Auth.Server.Tests;

public sealed class DpopIntegrationTests
{
    private static readonly Uri TokenUri = new("https://localhost/connect/token");

    [RedisFact]
    public async Task NonceProofAndIntrospection_BindMachineToken_AndRejectProofReplay()
    {
        using var factory = new DpopFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256);
        var form = MachineForm();
        using var challenge = await Token(client, form, DpopProof.Create(credentials, "POST", TokenUri));
        Assert.Equal("use_dpop_nonce", await Error(challenge));
        var nonce = challenge.Headers.GetValues("DPoP-Nonce").Single();
        var proof = DpopProof.Create(credentials, "POST", TokenUri, nonce: nonce);
        using var issued = await Token(client, form, proof);
        Assert.True(issued.IsSuccessStatusCode, await issued.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(await issued.Content.ReadAsStringAsync());
        Assert.Equal("DPoP", body.RootElement.GetProperty("token_type").GetString());
        var access = body.RootElement.GetProperty("access_token").GetString()!;
        var jwt = new JsonWebToken(access);
        Assert.Equal(Thumbprint(credentials), jwt.GetPayloadValue<JsonElement>("cnf").GetProperty("jkt").GetString());
        using var replay = await Token(client, form, proof);
        Assert.Equal("invalid_dpop_proof", await Error(replay));
        using var introspection = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "andy-docs-api", ["client_secret"] = CustomWebApplicationFactory.AndyDocsApiClientSecret, ["token"] = access
        }));
        using var details = JsonDocument.Parse(await introspection.Content.ReadAsStringAsync());
        Assert.True(details.RootElement.GetProperty("active").GetBoolean(), await introspection.Content.ReadAsStringAsync());
        Assert.Equal("DPoP", details.RootElement.GetProperty("token_type").GetString());
        Assert.Equal(Thumbprint(credentials), details.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
        using var metadata = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        Assert.Equal(new[] { "ES256", "RS256" }, metadata.RootElement.GetProperty("dpop_signing_alg_values_supported")
            .EnumerateArray().Select(value => value.GetString()).ToArray());
    }

    [RedisFact]
    public async Task CodeRefreshAndResourceUsage_KeepTheOriginalKeyAndRejectBearerDowngrade()
    {
        using var factory = new DpopFactory();
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        using var rsa = RSA.Create(2048);
        var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var csrf = Regex.Match(await browser.GetStringAsync("/Account/Login"), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        using var login = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = CustomWebApplicationFactory.AdminEmail, ["Password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = csrf
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        const string callback = "http://localhost:4200/auth/callback";
        using var authorize = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "andy-docs-web", ["redirect_uri"] = callback, ["response_type"] = "code", ["scope"] = "openid roles offline_access urn:andy-docs-api",
            ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))), ["code_challenge_method"] = "S256",
            ["dpop_jkt"] = Thumbprint(credentials)
        }));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var code = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"].ToString();
        var form = new Dictionary<string, string>
        {
            ["client_id"] = "andy-docs-web", ["grant_type"] = "authorization_code", ["redirect_uri"] = callback,
            ["code"] = code, ["code_verifier"] = verifier
        };
        using var challenge = await Token(browser, form, DpopProof.Create(credentials, "POST", TokenUri));
        Assert.Equal("use_dpop_nonce", await Error(challenge));
        var nonce = challenge.Headers.GetValues("DPoP-Nonce").Single();
        using var issued = await Token(browser, form, DpopProof.Create(credentials, "POST", TokenUri, nonce: nonce));
        Assert.True(issued.IsSuccessStatusCode, await issued.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(await issued.Content.ReadAsStringAsync());
        var access = body.RootElement.GetProperty("access_token").GetString()!;
        var refresh = body.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.Equal(Thumbprint(credentials), new JsonWebToken(access).GetPayloadValue<JsonElement>("cnf").GetProperty("jkt").GetString());
        using var api = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using var good = await Resource(api, access, DpopProof.Create(credentials, "GET", new Uri("https://localhost/api/users"), access));
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        using var bearer = await Resource(api, access, null, "Bearer");
        Assert.Equal(HttpStatusCode.Unauthorized, bearer.StatusCode);
        using var badHash = await Resource(api, access, DpopProof.Create(credentials, "GET", new Uri("https://localhost/api/users"), access + "wrong"));
        Assert.Equal(HttpStatusCode.Unauthorized, badHash.StatusCode);
        var refreshForm = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["client_id"] = "andy-docs-web", ["refresh_token"] = refresh };
        using var unboundRefresh = await Token(browser, refreshForm, null);
        Assert.Equal("invalid_dpop_proof", await Error(unboundRefresh));
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongCredentials = new SigningCredentials(new ECDsaSecurityKey(otherKey), SecurityAlgorithms.EcdsaSha256);
        using var wrongChallenge = await Token(browser, refreshForm, DpopProof.Create(wrongCredentials, "POST", TokenUri));
        Assert.Equal("use_dpop_nonce", await Error(wrongChallenge));
        using var wrongRefresh = await Token(browser, refreshForm, DpopProof.Create(wrongCredentials, "POST", TokenUri,
            nonce: wrongChallenge.Headers.GetValues("DPoP-Nonce").Single()));
        Assert.Equal("invalid_dpop_proof", await Error(wrongRefresh));
        using var wrongResource = await Resource(api, access, DpopProof.Create(wrongCredentials, "GET", new Uri("https://localhost/api/users"), access));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongResource.StatusCode);
        var resourceProof = DpopProof.Create(credentials, "GET", new Uri("https://localhost/api/users"), access);
        using var firstResource = await Resource(api, access, resourceProof);
        Assert.Equal(HttpStatusCode.OK, firstResource.StatusCode);
        using var replayResource = await Resource(api, access, resourceProof);
        Assert.Equal(HttpStatusCode.Unauthorized, replayResource.StatusCode);
        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("DPoP", access);
        userInfoRequest.Headers.Add("DPoP", DpopProof.Create(credentials, "GET", new Uri("https://localhost/connect/userinfo"), access));
        using var userInfo = await api.SendAsync(userInfoRequest);
        Assert.True(userInfo.IsSuccessStatusCode, await userInfo.Content.ReadAsStringAsync());
        using var renewed = await Token(browser, refreshForm, DpopProof.Create(credentials, "POST", TokenUri, nonce: nonce));
        Assert.True(renewed.IsSuccessStatusCode, await renewed.Content.ReadAsStringAsync());
        using var renewedBody = JsonDocument.Parse(await renewed.Content.ReadAsStringAsync());
        Assert.Equal(Thumbprint(credentials), new JsonWebToken(renewedBody.RootElement.GetProperty("access_token").GetString()!)
            .GetPayloadValue<JsonElement>("cnf").GetProperty("jkt").GetString());
        using var scope = factory.Services.CreateScope();
        Assert.False((await scope.ServiceProvider.GetRequiredService<ISubjectTokenValidator>().ValidateAsync(access)).IsValid);
        using var consumer = await LiveConsumerFixture.StartAsync(factory, new JsonWebToken(access), dpop: true);
        using var resourceClient = consumer.GetTestClient();
        resourceClient.BaseAddress = new Uri("https://resource.example");
        async Task<HttpResponseMessage> CallConsumer()
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/sensitive");
            request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", access);
            request.Headers.Add("DPoP", DpopProof.Create(credentials, "GET", new Uri("https://resource.example/sensitive"), access));
            return await resourceClient.SendAsync(request);
        }
        using var live = await CallConsumer();
        Assert.True(live.IsSuccessStatusCode, await live.Content.ReadAsStringAsync());
        var sessionId = new JsonWebToken(access).GetClaim("session_id").Value;
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.UserSessions.Where(row => row.SessionId == sessionId).ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsRevoked, true));
        using var revoked = await CallConsumer();
        Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
    }

    [RedisFact]
    public async Task ClientRequirement_RejectsMissingProof_AndProofStoreOutageIsTransient()
    {
        using var factory = new DpopFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        using (var scope = factory.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = (await manager.FindByClientIdAsync("andy-docs-api"))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, application);
            descriptor.Requirements.Add(DpopBinding.Requirement);
            await manager.UpdateAsync(application, descriptor);
        }
        using var missing = await Token(client, MachineForm(), null);
        Assert.Equal("invalid_dpop_proof", await Error(missing));
        using var broken = new DpopFactory(broken: true);
        using var brokenClient = broken.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256);
        using var challenge = await Token(brokenClient, MachineForm(), DpopProof.Create(credentials, "POST", TokenUri));
        var nonce = challenge.Headers.GetValues("DPoP-Nonce").Single();
        using var unavailable = await Token(brokenClient, MachineForm(), DpopProof.Create(credentials, "POST", TokenUri, nonce: nonce));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("temporarily_unavailable", await Error(unavailable));
        using var resource = await Resource(brokenClient, "unused", DpopProof.Create(credentials, "GET", new Uri("https://localhost/api/users"), "unused"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resource.StatusCode);
    }

    [RedisFact]
    public async Task SharedReplayProtection_ReservesOnceUnderLoad_AndSurvivesValidatorRestart()
    {
        var connectionString = Environment.GetEnvironmentVariable("ANDY_TEST_REDIS")!;
        using var first = await ConnectionMultiplexer.ConnectAsync(connectionString);
        using var second = await ConnectionMultiplexer.ConnectAsync(connectionString);
        var validators = new[] { new DpopProofValidator(new RedisDpopReplayStore(first), TimeProvider.System),
            new DpopProofValidator(new RedisDpopReplayStore(second), TimeProvider.System) };
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256);
        var proof = DpopProof.Create(credentials, "POST", TokenUri);
        var results = await Task.WhenAll(Enumerable.Range(0, 100).Select(index => validators[index % 2]
            .ValidateAsync(proof, "POST", TokenUri, TimeSpan.FromMinutes(1))));
        Assert.Equal(1, results.Count(result => result.Succeeded));
        using var restarted = await ConnectionMultiplexer.ConnectAsync(connectionString);
        Assert.False((await new DpopProofValidator(new RedisDpopReplayStore(restarted), TimeProvider.System)
            .ValidateAsync(proof, "POST", TokenUri, TimeSpan.FromMinutes(1))).Succeeded);
    }

    private static Dictionary<string, string> MachineForm() => new()
    {
        ["grant_type"] = "client_credentials", ["client_id"] = "andy-docs-api",
        ["client_secret"] = CustomWebApplicationFactory.AndyDocsApiClientSecret, ["scope"] = "urn:andy-docs-api"
    };
    private static string Thumbprint(SigningCredentials credentials) => Base64UrlEncoder.Encode(JsonWebKeyConverter.ConvertFromSecurityKey(credentials.Key).ComputeJwkThumbprint());
    private static async Task<string?> Error(HttpResponseMessage response)
    {
        Assert.False(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("error").GetString();
    }
    private static async Task<HttpResponseMessage> Token(HttpClient client, Dictionary<string, string> form, string? proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token") { Content = new FormUrlEncodedContent(form) };
        if (proof != null) request.Headers.Add("DPoP", proof);
        return await client.SendAsync(request);
    }
    private static async Task<HttpResponseMessage> Resource(HttpClient client, string access, string? proof, string scheme = "DPoP")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/users");
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, access);
        if (proof != null) request.Headers.Add("DPoP", proof);
        return await client.SendAsync(request);
    }

    private sealed class BrokenStore : IDpopReplayStore
    {
        public Task<bool> TryUseAsync(string thumbprint, string id, TimeSpan retention, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Replay backend unavailable");
    }

    private sealed class DpopFactory : CustomWebApplicationFactory
    {
        private readonly Dictionary<string, string?> previous = new();
        private readonly bool broken;
        public DpopFactory(bool broken = false)
        {
            this.broken = broken;
            Set("OpenIddict__AdvancedFlows__DPoP__Enabled", "true");
            Set("RateLimiting__RedisConnectionString", Environment.GetEnvironmentVariable("ANDY_TEST_REDIS")!);
        }
        private void Set(string key, string value) { previous[key] = Environment.GetEnvironmentVariable(key); Environment.SetEnvironmentVariable(key, value); }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
            {
                services.Configure<IpRateLimitOptions>(options => options.GeneralRules = new());
                if (broken) services.Replace(ServiceDescriptor.Singleton<IDpopReplayStore, BrokenStore>());
            });
        }
        protected override void Dispose(bool disposing)
        {
            foreach (var pair in previous) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            base.Dispose(disposing);
        }
    }
}
