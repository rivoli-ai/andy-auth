using System.Net;
using System.Text.Json;
using AspNetCoreRateLimit;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Andy.Auth.Server.Tests;

// IStartupFilter that pins a deterministic connection RemoteIpAddress before
// UseForwardedHeaders runs. TestServer leaves RemoteIpAddress null, which the
// forwarded-headers middleware cannot range-check; pinning a concrete peer lets
// the spoofing tests exercise the trusted/untrusted-peer branches.
internal sealed class RemoteIpStartupFilter : IStartupFilter
{
    private readonly IPAddress _peer;
    public RemoteIpStartupFilter(IPAddress peer) => _peer = peer;

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            context.Connection.RemoteIpAddress = _peer;
            await nextMiddleware();
        });
        next(app);
    };
}

// Pins andy-auth#125: forwarded headers and the rate-limit client identity must
// only be honoured from trusted proxies, so an attacker cannot spoof their IP
// (evading login/token rate limits, contaminating audit/session records) or
// scheme via X-Forwarded-*/X-Real-IP.
//
// The HTTP-surface tests drive an anonymous diagnostics endpoint
// (/internal/client-info, opt-in via Diagnostics:EnableClientInfoEndpoint) that
// echoes the post-ForwardedHeaders RemoteIpAddress + scheme.
public class ForwardedHeadersTrustTests : IDisposable
{
    private const string SpoofedIp = "203.0.113.7";      // TEST-NET-3, never a real peer
    private const string SpoofedRealIp = "198.51.100.9"; // TEST-NET-2
    // Deterministic connection peer for the HTTP tests: outside the restricted
    // trust range (203.0.113.128/25) so it is treated as untrusted there.
    private static readonly IPAddress UntrustedPeer = IPAddress.Parse("192.0.2.50"); // TEST-NET-1

    private readonly string _baseTemp;

    public ForwardedHeadersTrustTests()
    {
        _baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-fwd-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_baseTemp);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_baseTemp))
            {
                Directory.Delete(_baseTemp, recursive: true);
            }
        }
        catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task TrustAllProxies_HonoursForwardedFor()
    {
        // Local-development trust model (base default TrustAllProxies=true):
        // forwarded headers ARE applied. This is the behaviour local proxies
        // (Conductor unified proxy) depend on.
        using var factory = CreateFactory(HostEnvironmentExtensions.EmbeddedEnvironmentName,
            trustAllProxies: true, peer: UntrustedPeer);
        using var client = HttpClient(factory);

        var info = await GetClientInfoAsync(client, forwardedFor: SpoofedIp);

        info.Ip.Should().Be(SpoofedIp,
            "with TrustAllProxies=true the middleware honours X-Forwarded-For from any peer");
    }

    [Fact]
    public async Task RestrictedProxies_IgnoresSpoofedForwardedFor()
    {
        // Restricted trust set (Production/UAT model): the in-memory test peer
        // is not inside KnownNetworks, so a spoofed X-Forwarded-For is dropped
        // and cannot become the client identity.
        using var factory = CreateFactory(HostEnvironmentExtensions.EmbeddedEnvironmentName,
            trustAllProxies: false, knownNetwork: "203.0.113.128/25", peer: UntrustedPeer);
        using var client = HttpClient(factory);

        var info = await GetClientInfoAsync(client, forwardedFor: SpoofedIp);

        info.Ip.Should().Be(UntrustedPeer.ToString(),
            "an untrusted peer must not be able to forge its client IP via X-Forwarded-For (#125)");
        info.Ip.Should().NotBe(SpoofedIp);
    }

    [Fact]
    public async Task RestrictedProxies_IgnoresSpoofedForwardedProto()
    {
        // A spoofed X-Forwarded-Proto=https from an untrusted peer must be
        // ignored, so the request scheme stays http (what the connection used).
        using var factory = CreateFactory(HostEnvironmentExtensions.EmbeddedEnvironmentName,
            trustAllProxies: false, knownNetwork: "203.0.113.128/25", peer: UntrustedPeer);
        using var client = HttpClient(factory);

        var info = await GetClientInfoAsync(client, forwardedProto: "https");

        info.Scheme.Should().Be("http",
            "an untrusted peer must not be able to forge the request scheme via X-Forwarded-Proto (#125)");
    }

    [Fact]
    public async Task XRealIp_DoesNotBecomeClientIdentity()
    {
        // X-Real-IP is a raw caller-supplied header; UseForwardedHeaders never
        // processes it, and rate limiting no longer reads it (see the options
        // test below). So it must never surface as the resolved client IP.
        using var factory = CreateFactory(HostEnvironmentExtensions.EmbeddedEnvironmentName,
            trustAllProxies: true, peer: UntrustedPeer);
        using var client = HttpClient(factory);

        var info = await GetClientInfoAsync(client, realIp: SpoofedRealIp);

        info.Ip.Should().Be(UntrustedPeer.ToString(),
            "X-Real-IP is never processed by UseForwardedHeaders, so the connection peer is preserved");
        info.Ip.Should().NotBe(SpoofedRealIp,
            "X-Real-IP must not influence the resolved client IP (#125)");
    }

    [Fact]
    public void RateLimiting_DoesNotTrustXRealIpHeader()
    {
        // The rate limiter must resolve the client IP from the normalised
        // connection, not from a spoofable header. An empty RealIpHeader makes
        // AspNetCoreRateLimit fall back to HttpContext.Connection.RemoteIpAddress.
        using var factory = CreateFactory("Development", trustAllProxies: true);

        var options = factory.Services.GetRequiredService<IOptions<IpRateLimitOptions>>().Value;

        options.RealIpHeader.Should().BeNullOrEmpty(
            "rate limiting must use the trusted connection IP, not a caller-supplied X-Real-IP (#125)");
    }

    [Theory]
    [InlineData("Development")]
    [InlineData(HostEnvironmentExtensions.DockerEnvironmentName)]
    [InlineData(HostEnvironmentExtensions.EmbeddedEnvironmentName)]
    public void LocalModes_TrustAllProxiesByDefault(string environmentName)
    {
        // Local-development modes inherit the base TrustAllProxies=true, which
        // clears the known-proxy set (empty => accept from any peer).
        using var factory = CreateFactory(environmentName, trustAllProxies: null);

        var options = factory.Services
            .GetRequiredService<IOptions<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>>().Value;

        options.KnownNetworks.Should().BeEmpty();
        options.KnownProxies.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("UAT")]
    public void HostedModes_RestrictForwardedHeadersToTrustedNetworks(string environmentName)
    {
        // Production/UAT ship TrustAllProxies=false + an explicit KnownNetworks
        // list, so forwarded headers are only honoured from those ranges.
        using var factory = CreateFactory(environmentName, trustAllProxies: null,
            keysPath: Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"), "keys"));

        var options = factory.Services
            .GetRequiredService<IOptions<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>>().Value;

        options.KnownNetworks.Should().NotBeEmpty(
            $"{environmentName} must restrict forwarded headers to a trusted proxy network set (#125)");
    }

    private EnvironmentWebApplicationFactory CreateFactory(
        string environmentName,
        bool? trustAllProxies,
        string? knownNetwork = null,
        string? keysPath = null,
        IPAddress? peer = null)
    {
        var modeDir = Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(modeDir);

        var extra = new List<KeyValuePair<string, string?>>
        {
            new("Diagnostics__EnableClientInfoEndpoint", "true"),
        };
        if (trustAllProxies is bool trust)
        {
            extra.Add(new("ForwardedHeaders__TrustAllProxies", trust ? "true" : "false"));
        }
        if (knownNetwork is not null)
        {
            extra.Add(new("ForwardedHeaders__KnownNetworks__0", knownNetwork));
        }

        // Production requires signing keys; provide a path so boot succeeds.
        var effectiveKeys = keysPath
            ?? (environmentName == HostEnvironmentExtensions.EmbeddedEnvironmentName
                ? Path.Combine(modeDir, "keys")
                : null);

        Action<IServiceCollection>? configureTestServices = peer is null
            ? null
            : services => services.AddSingleton<IStartupFilter>(new RemoteIpStartupFilter(peer));

        return new EnvironmentWebApplicationFactory(
            environmentName: environmentName,
            dbPath: Path.Combine(modeDir, "andy-auth.sqlite"),
            issuer: environmentName is "Production" or "UAT"
                ? "https://auth.example.test/"
                : "http://localhost:9100/auth/",
            keysPath: effectiveKeys,
            extraEnvironment: extra,
            configureTestServices: configureTestServices);
    }

    private static HttpClient HttpClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("http://localhost/")
        });

    private static async Task<ClientInfo> GetClientInfoAsync(
        HttpClient client,
        string? forwardedFor = null,
        string? forwardedProto = null,
        string? realIp = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/internal/client-info");
        if (forwardedFor is not null) request.Headers.Add("X-Forwarded-For", forwardedFor);
        if (forwardedProto is not null) request.Headers.Add("X-Forwarded-Proto", forwardedProto);
        if (realIp is not null) request.Headers.Add("X-Real-IP", realIp);

        var response = await client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        return new ClientInfo(
            root.TryGetProperty("ip", out var ip) ? ip.GetString() : null,
            root.TryGetProperty("scheme", out var scheme) ? scheme.GetString() : null);
    }

    private sealed record ClientInfo(string? Ip, string? Scheme);
}
