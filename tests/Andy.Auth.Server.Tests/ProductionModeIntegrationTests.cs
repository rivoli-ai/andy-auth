using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Production rejects local-only keys and publishes stable protected credentials.
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
    public async Task ProductionBoot_WithProtectedCertificates_ServesDiscovery()
    {
        using var factory = ProductionFactory(keysPath: _keysDir, useEphemeralKeys: false);
        using var client = HttpsClient(factory);

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        File.Exists(Path.Combine(_keysDir, "signing.pfx")).Should().BeTrue();
        File.Exists(Path.Combine(_keysDir, "signing.key")).Should().BeFalse();
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
            "Production with protected certificates must keep JWKS " +
            "stable across redeploys; otherwise every issued JWT goes " +
            "invalid on container restart");
    }

    [Fact]
    public async Task JwksPublishesFutureSigningCertificateBeforeActivation()
    {
        var fixture = new Configuration.ProductionKeyFixture(_keysDir);
        fixture.Add("OpenIddict:Certificates:Signing:1", "future", DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow.AddDays(60));
        using var factory = new EnvironmentWebApplicationFactory("Production", _dbPath,
            "https://auth.example.test/", keysPath: _keysDir,
            extraEnvironment: fixture.Values.Select(kv => new KeyValuePair<string, string?>(kv.Key.Replace(":", "__"), kv.Value)));
        using var client = HttpsClient(factory);
        using var discovery = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        var uri = new Uri(discovery.RootElement.GetProperty("jwks_uri").GetString()!);
        using var jwks = JsonDocument.Parse(await client.GetStringAsync(uri.AbsolutePath));
        jwks.RootElement.GetProperty("keys").GetArrayLength().Should().Be(2);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ProductionBoot_WithLegacyKeys_Throws(bool ephemeral)
    {
        using var factory = new EnvironmentWebApplicationFactory("Production", _dbPath,
            "https://auth.example.test/", keysPath: ephemeral ? null : _keysDir,
            useEphemeralKeys: ephemeral, provisionProductionKeys: false);
        var act = () => factory.CreateClient();
        act.Should().Throw<InvalidOperationException>().WithMessage("*protected certificate bundles*");
    }

    [Fact]
    public void ProductionBoot_WithoutCertificates_Throws()
    {
        using var factory = new EnvironmentWebApplicationFactory("Production", _dbPath,
            "https://auth.example.test/", provisionProductionKeys: false);
        var act = () => factory.CreateClient();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Certificates:Signing*");
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
