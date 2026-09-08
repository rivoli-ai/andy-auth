using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Andy.Auth.Extensions;
using Andy.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Andy.Auth.Tests.Integration;

public sealed class LiveSessionIntegrationTests
{
    private const string Authority = "https://auth.example.test/";
    private const string Live = "{\"authenticated\":true,\"revoked\":false,\"subject\":\"user-1\",\"sessionId\":\"session-1\"}";

    [Theory]
    [InlineData(410, "", 401)]
    [InlineData(401, "", 401)]
    [InlineData(403, "", 401)]
    [InlineData(503, "", 503)]
    [InlineData(429, "", 503)]
    [InlineData(302, "", 503)]
    [InlineData(200, "invalid", 503)]
    [InlineData(200, "{}", 503)]
    [InlineData(200, "{\"authenticated\":false,\"revoked\":true}", 401)]
    [InlineData(200, "{\"authenticated\":true,\"revoked\":false,\"subject\":\"other\",\"sessionId\":\"session-1\"}", 401)]
    [InlineData(200, "{\"authenticated\":true,\"revoked\":false,\"subject\":\"user-1\",\"sessionId\":\"other\"}", 401)]
    public async Task PreviouslyAcceptedTokenCannotBypassChangedTruth(int upstreamStatus, string body, int expected)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test" };
        var truth = new TruthHandler();
        using var host = await Host(key, truth);
        using var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token(key));
        using var first = await client.GetAsync("/protected");
        Assert.True(first.StatusCode == HttpStatusCode.OK, $"{first.StatusCode}; calls={truth.Calls}; {first.Headers.WwwAuthenticate}");
        truth.Status = (HttpStatusCode)upstreamStatus;
        truth.Body = body;
        using var second = await client.GetAsync("/protected");
        Assert.Equal(expected, (int)second.StatusCode);
        Assert.Equal(2, truth.Calls);
        if (expected == 503)
        {
            Assert.True(second.Headers.CacheControl?.NoStore);
            Assert.Equal(TimeSpan.FromSeconds(5), second.Headers.RetryAfter?.Delta);
        }
    }

    [Theory]
    [InlineData("secevent+jwt", "api", true, false)]
    [InlineData("at+jwt", "other-api", true, false)]
    [InlineData("at+jwt", "api", false, false)]
    [InlineData("at+jwt", "api", true, true)]
    public async Task WrongTokenTypeAudienceOrMissingSessionNeverReachesTruth(string type, string audience, bool session, bool expired)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test" };
        var truth = new TruthHandler();
        using var host = await Host(key, truth);
        using var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token(key, type, audience, session, expired));
        using var response = await client.GetAsync("/protected");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, truth.Calls);
    }

    [Fact]
    public async Task DependencyTimeoutFailsClosedAndPreservesCustomEvents()
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test" };
        var truth = new TruthHandler { Throw = true };
        var customCalls = 0;
        var events = new JwtBearerEvents { OnTokenValidated = _ => { customCalls++; return Task.CompletedTask; } };
        var original = events.OnTokenValidated;
        using var host = await Host(key, truth, events);
        using var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token(key));
        using var response = await client.GetAsync("/protected");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, customCalls);
        Assert.Same(original, events.OnTokenValidated);
    }

    private static string Token(SecurityKey key, string type = "at+jwt", string audience = "api", bool session = true, bool expired = false)
    {
        var claims = new Dictionary<string, object> { ["sub"] = "user-1" };
        if (session) claims["session_id"] = "session-1";
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority, Audience = audience, Claims = claims, TokenType = type,
            IssuedAt = DateTime.UtcNow.AddMinutes(-1), NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = expired ? DateTime.UtcNow.AddSeconds(-10) : DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });
    }

    private static Task<IHost> Host(SecurityKey key, TruthHandler truth, JwtBearerEvents? events = null) =>
        new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddAndyAuth(options =>
            {
                options.Authority = Authority;
                options.Audience = "api";
                options.RequireLiveSession = true;
                options.Events = events;
            });
            services.AddHttpClient(LiveSessionValidation.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => truth);
            services.PostConfigure<JwtBearerOptions>("Bearer", options =>
            {
                options.Configuration = new OpenIdConnectConfiguration { Issuer = Authority };
                options.Configuration.SigningKeys.Add(key);
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
            });
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapGet("/protected", context => context.Response.WriteAsync("allowed"))
                .RequireAuthorization());
        })).StartAsync();

    private sealed class TruthHandler : HttpMessageHandler
    {
        public HttpStatusCode Status = HttpStatusCode.OK;
        public string Body = Live;
        public int Calls;
        public bool Throw;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            Assert.Equal(Authority + "auth/session", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.True(request.Headers.CacheControl?.NoCache);
            Assert.True(request.Headers.CacheControl?.NoStore);
            if (Throw) throw new TaskCanceledException();
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Body, Encoding.UTF8, "application/json") });
        }
    }
}
