using System.Net;
using System.Text.Json;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Cross-mode parity smoke for the OIDC discovery contract. Each
// supported deployment mode (Embedded, Production-with-keys,
// Production-with-ephemeral-keys) must serve a discovery doc with
// the configured issuer and S256 PKCE advertised — otherwise a
// consumer service that boots in one mode would fail to validate
// tokens minted by andy-auth in another.
//
// Demonstrates the value of `EnvironmentWebApplicationFactory` —
// adding a new mode is one factory call, no boilerplate.
public class CrossModeDiscoveryTests : IDisposable
{
    private readonly string _baseTemp;

    public CrossModeDiscoveryTests()
    {
        _baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-crossmode-tests-" + Guid.NewGuid().ToString("N"));
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

    public static IEnumerable<object[]> Modes => new[]
    {
        new object[] { Mode.Embedded, "http://localhost:9100/auth/" },
        new object[] { Mode.ProductionPersistedKeys, "https://auth.example.test/" },
        new object[] { Mode.ProductionEphemeralKeys, "https://auth.example.test/" },
    };

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task DiscoveryDoc_AdvertisesConfiguredIssuerAndPkceMethods(Mode mode, string issuer)
    {
        using var factory = CreateFactory(mode, issuer);
        using var client = ClientFor(factory, mode);

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.GetProperty("issuer").GetString().Should().Be(issuer,
            "every mode must surface its configured issuer in the discovery doc");

        var methods = doc.RootElement
            .GetProperty("code_challenge_methods_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        methods.Should().Contain("S256",
            "PKCE S256 is the only accepted method server-wide (closes #46)");

        doc.RootElement.GetProperty("jwks_uri").GetString()
            .Should().NotBeNullOrEmpty("every mode must publish a jwks_uri");
    }

    private EnvironmentWebApplicationFactory CreateFactory(Mode mode, string issuer)
    {
        var modeDir = Path.Combine(_baseTemp, mode.ToString());
        Directory.CreateDirectory(modeDir);
        var dbPath = Path.Combine(modeDir, "andy-auth.sqlite");
        var keysPath = Path.Combine(modeDir, "keys");

        return mode switch
        {
            Mode.Embedded => new EnvironmentWebApplicationFactory(
                environmentName: HostEnvironmentExtensions.EmbeddedEnvironmentName,
                dbPath: dbPath,
                issuer: issuer,
                keysPath: keysPath),

            Mode.ProductionPersistedKeys => new EnvironmentWebApplicationFactory(
                environmentName: "Production",
                dbPath: dbPath,
                issuer: issuer,
                keysPath: keysPath),

            Mode.ProductionEphemeralKeys => new EnvironmentWebApplicationFactory(
                environmentName: "Production",
                dbPath: dbPath,
                issuer: issuer,
                keysPath: null,
                useEphemeralKeys: true),

            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null)
        };
    }

    private static HttpClient ClientFor(WebApplicationFactory<Program> factory, Mode mode)
    {
        // Embedded calls DisableTransportSecurityRequirement(); HTTP is fine.
        // Production keeps OpenIddict's HTTPS-only requirement, so the
        // in-memory client must speak https://. TestServer fakes both.
        var baseAddress = mode == Mode.Embedded
            ? new Uri("http://localhost/")
            : new Uri("https://localhost/");

        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = baseAddress
        });
    }

    public enum Mode
    {
        Embedded,
        ProductionPersistedKeys,
        ProductionEphemeralKeys
    }
}
