using System.Net;
using System.Security.Cryptography;
using System.Text;
using Andy.Auth.Revocation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Andy.Auth.Tests.Revocation;

public sealed class RevocationReceiverTests
{
    private const string Issuer = "https://issuer.test/";

    [Theory]
    [InlineData("issuer")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("missing-iat")]
    [InlineData("expired")]
    [InlineData("jti")]
    [InlineData("event")]
    [InlineData("multiple-events")]
    [InlineData("sid")]
    [InlineData("control-sid")]
    [InlineData("future-occurrence")]
    [InlineData("unsigned")]
    public async Task InvalidEventIsNotPersisted(string mutation)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "active" };
        using var host = await Host(key);
        using var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://receiver.test");
        using var response = await client.PostAsync("/events", Body(Token(key, mutation)));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("en", response.Content.Headers.ContentLanguage);
        Assert.False(await host.Services.GetRequiredService<IRevokedSessionStore>().IsRevokedAsync(Issuer, "session", default));
    }

    [Fact]
    public async Task UnknownSigningKeyRequestsRetry_ThenReceiptAndReplayPersistOneDenial()
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "active" };
        using var host = await Host(key);
        using var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://receiver.test");
        var keys = host.Services.GetRequiredService<RevocationReceiverKeys>();
        keys.Manager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new() { Issuer = Issuer });
        var token = Token(key);
        using var unknown = await client.PostAsync("/events", Body(token));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unknown.StatusCode);
        var metadata = new OpenIdConnectConfiguration { Issuer = Issuer };
        metadata.SigningKeys.Add(key);
        keys.Manager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata);
        for (var i = 0; i < 2; i++)
        {
            using var received = await client.PostAsync("/events", Body(token));
            Assert.Equal(HttpStatusCode.Accepted, received.StatusCode);
            Assert.Empty(await received.Content.ReadAsByteArrayAsync());
        }
        var store = host.Services.GetRequiredService<IRevokedSessionStore>();
        Assert.True(await store.IsRevokedAsync(Issuer, "session", default));
        Assert.True(await store.IsRevokedAsync(Issuer.TrimEnd('/'), "session", default));
        Assert.False(await store.IsRevokedAsync("https://other.test/", "session", default));
    }

    [Fact]
    public async Task TransportAndSizeConstraintsApplyBeforeReceipt()
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "active" };
        using var host = await Host(key);
        using var client = host.GetTestClient();
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("http://receiver.test/events", Body(Token(key)))).StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await client.PostAsync("https://receiver.test/events", new StringContent(Token(key)))).StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await client.PostAsync("https://receiver.test/events", Body(new string('a', 32769)))).StatusCode);
    }

    [Fact]
    public async Task ProductionRefusesProcessLocalReceiptStorage()
    {
        using var rsa = RSA.Create(2048);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Host(new RsaSecurityKey(rsa) { KeyId = "active" }, "Production"));
    }

    private static StringContent Body(string token) => new(token, Encoding.ASCII, "application/secevent+jwt");

    private static string Token(SecurityKey key, string mutation = "")
    {
        var now = DateTimeOffset.UtcNow;
        var events = new Dictionary<string, object>
        {
            [mutation == "event" ? "urn:unknown" : RevocationReceiver.EventType] = new Dictionary<string, object>
            {
                ["sid"] = mutation == "sid" ? "" : mutation == "control-sid" ? "session\n" : "session",
                ["occurred_at"] = mutation == "future-occurrence" ? now.AddDays(1).ToUnixTimeSeconds() : now.AddMinutes(-10).ToUnixTimeSeconds()
            }
        };
        if (mutation == "multiple-events") events["urn:extra"] = new Dictionary<string, object>();
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "secevent+jwt", Issuer = mutation == "issuer" ? "https://other.test/" : Issuer, Audience = "receiver",
            IssuedAt = mutation == "missing-iat" ? null : mutation == "stale" ? now.AddMinutes(-6).UtcDateTime :
                mutation == "future" ? now.AddMinutes(2).UtcDateTime : now.UtcDateTime,
            Expires = mutation == "expired" ? now.AddSeconds(-1).UtcDateTime : null,
            SigningCredentials = mutation == "unsigned" ? null : new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["jti"] = mutation == "jti" ? "" : Guid.NewGuid().ToString("N"), ["events"] = events }
        });
    }

    private static Task<IHost> Host(SecurityKey key, string environment = "Testing") =>
        new HostBuilder().UseEnvironment(environment).ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddDistributedMemoryCache();
            services.AddAndyRevocationReceiver(options => { options.Authority = Issuer; options.Audience = "receiver"; });
            var metadata = new OpenIdConnectConfiguration { Issuer = Issuer };
            metadata.SigningKeys.Add(key);
            services.AddSingleton(provider => new RevocationReceiverKeys(provider.GetRequiredService<IOptions<RevocationReceiverOptions>>(),
                provider.GetRequiredService<IHttpClientFactory>()) { Manager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata) });
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapAndyRevocationEvents("/events"));
        })).StartAsync();
}
