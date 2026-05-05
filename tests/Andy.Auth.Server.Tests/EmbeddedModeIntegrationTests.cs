using System.Net;
using System.Text.Json;
using Andy.Auth.Server.Configuration;
using FluentAssertions;

namespace Andy.Auth.Server.Tests;

// Integration tests for ASPNETCORE_ENVIRONMENT=Embedded — the deployment
// mode used by Conductor when it bundles andy-auth as a child process.
//
// The invariants under test are the ones the Embedded-mode fix hinges on:
//   1. JWKS is stable across bootstraps when a keys path is configured.
//      This is what makes "user relaunches Conductor" not invalidate
//      every cached JWT.
//   2. The discovery document's `issuer` matches what was injected via
//      `OpenIddict:Issuer` — not the hardcoded `https://localhost:5001/`
//      that used to live in Program.cs.
//   3. Embedded mode hard-fails boot if `OpenIddict:SigningKeys:Path` is
//      missing, instead of silently falling back to ephemeral keys (the
//      bug this whole effort exists to fix).
//   4. Developer exception pages are NOT exposed in Embedded mode — a
//      shipping desktop app must not leak stack traces to its UI.
public class EmbeddedModeIntegrationTests : IDisposable
{
    private readonly string _keysDir;
    private readonly string _dbPath;

    public EmbeddedModeIntegrationTests()
    {
        var baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-embedded-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseTemp);
        _keysDir = Path.Combine(baseTemp, "keys");
        _dbPath = Path.Combine(baseTemp, "andy-auth.sqlite");
    }

    public void Dispose()
    {
        try
        {
            var parent = Path.GetDirectoryName(_keysDir);
            if (parent != null && Directory.Exists(parent))
            {
                Directory.Delete(parent, recursive: true);
            }
        }
        catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    private EnvironmentWebApplicationFactory CreateFactory(
        string? keysPathOverride = null,
        string? issuerOverride = null)
    {
        return new EnvironmentWebApplicationFactory(
            environmentName: HostEnvironmentExtensions.EmbeddedEnvironmentName,
            dbPath: _dbPath,
            issuer: issuerOverride ?? "http://localhost:9100/auth/",
            keysPath: keysPathOverride ?? _keysDir);
    }

    [Fact]
    public async Task EmbeddedBoot_PersistsKeysToDisk()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        // Touching any endpoint forces the OpenIddict server to initialise,
        // which is what triggers PersistedDevelopmentKeys on first call.
        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        File.Exists(Path.Combine(_keysDir, "signing.key")).Should().BeTrue();
        File.Exists(Path.Combine(_keysDir, "encryption.key")).Should().BeTrue();
    }

    [Fact]
    public async Task EmbeddedBoot_JwksIsStableAcrossRestarts()
    {
        // The headline invariant. Two independent factories sharing the
        // same keys directory must serve the same `kid` — otherwise the
        // Conductor "relaunch wipes tokens" bug recurs.
        string firstKid;
        using (var factory = CreateFactory())
        using (var client = factory.CreateClient())
        {
            firstKid = await GetFirstJwksKidAsync(client);
        }

        string secondKid;
        using (var factory = CreateFactory())
        using (var client = factory.CreateClient())
        {
            secondKid = await GetFirstJwksKidAsync(client);
        }

        secondKid.Should().Be(
            firstKid,
            "persisted keys must survive process restart; otherwise every " +
            "Conductor relaunch invalidates every cached JWT");
    }

    [Fact]
    public async Task EmbeddedBoot_ExposesConfiguredIssuerInDiscoveryDoc()
    {
        const string expected = "http://localhost:9100/auth/";
        using var factory = CreateFactory(issuerOverride: expected);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("issuer").GetString().Should().Be(
            expected,
            "OpenIddict:Issuer config must flow through SetIssuer; the " +
            "previous hardcoded https://localhost:5001/ would silently " +
            "break issuer validation in downstream services");
    }

    [Fact]
    public void EmbeddedBoot_WithoutKeysPath_ThrowsOnStartup()
    {
        var factory = new EnvironmentWebApplicationFactory(
            environmentName: HostEnvironmentExtensions.EmbeddedEnvironmentName,
            dbPath: _dbPath,
            issuer: "http://localhost:9100/auth/",
            keysPath: null);

        // Forcing CreateClient triggers the host build, which materialises
        // the OpenIddict server options — which is where our guard throws.
        var act = () =>
        {
            using var _ = factory.CreateClient();
        };

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Embedded mode requires `OpenIddict:SigningKeys:Path`*");

        factory.Dispose();
    }

    [Fact]
    public async Task EmbeddedBoot_DoesNotExposeDeveloperExceptionPage()
    {
        // We can't easily trigger a 500 mid-pipeline from here, but we can
        // assert the behavioural shape: hitting a route that should 404
        // returns a plain 404 (not a developer exception page HTML body
        // with stack trace). The existence of the dev page is conditioned
        // on `IsDevelopment()`, which Embedded is not.
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/no-such-path-for-dev-leak-check");
        var body = await response.Content.ReadAsStringAsync();

        body.Should().NotContain(
            "Developer Exception Page",
            "Embedded mode is a shipping deployment — no dev-page HTML leaks");
        body.Should().NotContain("HostingStartupAssembly");
    }

    private static async Task<string> GetFirstJwksKidAsync(HttpClient client)
    {
        // First fetch discovery to locate the JWKS URI (defensive — the
        // path is deterministic under OpenIddict but reading from the
        // doc keeps the test contract-compliant with any future change).
        var discovery = await client.GetAsync("/.well-known/openid-configuration");
        discovery.StatusCode.Should().Be(HttpStatusCode.OK);
        var discoveryJson = await discovery.Content.ReadAsStringAsync();
        using var discoveryDoc = JsonDocument.Parse(discoveryJson);
        var jwksUri = discoveryDoc.RootElement.GetProperty("jwks_uri").GetString();
        jwksUri.Should().NotBeNullOrEmpty();

        // The discovery doc advertises an absolute URL; convert to a
        // relative path for the in-process HttpClient.
        var uri = new Uri(jwksUri!);
        var relative = uri.AbsolutePath + uri.Query;

        var jwks = await client.GetAsync(relative);
        jwks.StatusCode.Should().Be(HttpStatusCode.OK);
        var jwksJson = await jwks.Content.ReadAsStringAsync();
        using var jwksDoc = JsonDocument.Parse(jwksJson);
        var keys = jwksDoc.RootElement.GetProperty("keys");
        keys.GetArrayLength().Should().BeGreaterThan(0);
        return keys[0].GetProperty("kid").GetString()!;
    }

}
