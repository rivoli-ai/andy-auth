using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Integration tests for ASPNETCORE_ENVIRONMENT=Production. The
// invariants here mirror the Embedded suite — the persisted-keys
// mechanism is shared — but cover the Production-only branching:
//   1. With `OpenIddict:SigningKeys:Path` set, RSA keys persist on
//      disk and JWKS `kid` survives a process restart. This is the
//      Railway-volume deploy shape (#69 / E3-S4).
//   2. With `OpenIddict:UseEphemeralKeys=true`, boot succeeds and
//      JWKS is served — stateless cloud-pod fallback.
//   3. With neither, boot hard-fails with a message that documents
//      both options. The previous placeholder behaviour was the
//      same throw but with a less specific message.
public class ProductionModeIntegrationTests : IDisposable
{
    private readonly string _keysDir;
    private readonly string _dbPath;

    public ProductionModeIntegrationTests()
    {
        var baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-prod-tests-" + Guid.NewGuid().ToString("N"));
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

    [Fact]
    public async Task ProductionBoot_WithKeysPath_PersistsKeysToDisk()
    {
        using var factory = ProductionFactory(keysPath: _keysDir, useEphemeralKeys: false);
        using var client = HttpsClient(factory);

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        File.Exists(Path.Combine(_keysDir, "signing.key")).Should().BeTrue();
        File.Exists(Path.Combine(_keysDir, "encryption.key")).Should().BeTrue();
    }

    [Fact]
    public async Task ProductionBoot_WithKeysPath_JwksIsStableAcrossRestarts()
    {
        // Headline invariant for #69: Railway redeploys must not
        // rotate JWKS, otherwise every issued token across every
        // consumer service goes invalid simultaneously.
        string firstKid;
        using (var factory = ProductionFactory(keysPath: _keysDir, useEphemeralKeys: false))
        using (var client = HttpsClient(factory))
        {
            firstKid = await GetFirstJwksKidAsync(client);
        }

        string secondKid;
        using (var factory = ProductionFactory(keysPath: _keysDir, useEphemeralKeys: false))
        using (var client = HttpsClient(factory))
        {
            secondKid = await GetFirstJwksKidAsync(client);
        }

        secondKid.Should().Be(
            firstKid,
            "Production with OpenIddict:SigningKeys:Path must keep JWKS " +
            "stable across redeploys; otherwise every issued JWT goes " +
            "invalid on container restart");
    }

    [Fact]
    public async Task ProductionBoot_WithEphemeralKeys_ServesJwks()
    {
        // Stateless-pod fallback: ephemeral keys are explicitly opted in.
        // Boot must succeed; JWKS must be served. The keys WILL rotate on
        // every restart (the documented trade-off) — not asserted here.
        using var factory = ProductionFactory(keysPath: null, useEphemeralKeys: true);
        using var client = HttpsClient(factory);

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var jwksUri = doc.RootElement.GetProperty("jwks_uri").GetString();
        jwksUri.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ProductionBoot_WithoutKeysPathOrEphemeralFlag_ThrowsOnStartup()
    {
        var factory = ProductionFactory(keysPath: null, useEphemeralKeys: false);

        var act = () =>
        {
            using var _ = factory.CreateClient();
        };

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*OpenIddict:SigningKeys:Path*UseEphemeralKeys*");

        factory.Dispose();
    }

    // Production keeps OpenIddict's HTTPS-only requirement (the
    // Embedded-mode `DisableTransportSecurityRequirement()` does not
    // apply here), so the in-memory test client must speak `https://`
    // to satisfy `Request.IsHttps == true` in the OpenIddict pipeline.
    // TestServer fakes both schemes — there is no real TLS handshake.
    private static HttpClient HttpsClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost/")
        });
        return client;
    }

    private static async Task<string> GetFirstJwksKidAsync(HttpClient client)
    {
        var discovery = await client.GetAsync("/.well-known/openid-configuration");
        discovery.StatusCode.Should().Be(HttpStatusCode.OK);
        var discoveryJson = await discovery.Content.ReadAsStringAsync();
        using var discoveryDoc = JsonDocument.Parse(discoveryJson);
        var jwksUri = discoveryDoc.RootElement.GetProperty("jwks_uri").GetString();
        jwksUri.Should().NotBeNullOrEmpty();

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

    private EnvironmentWebApplicationFactory ProductionFactory(string? keysPath, bool useEphemeralKeys)
    {
        return new EnvironmentWebApplicationFactory(
            environmentName: "Production",
            dbPath: _dbPath,
            issuer: "https://auth.example.test/",
            keysPath: keysPath,
            useEphemeralKeys: useEphemeralKeys);
    }
}
