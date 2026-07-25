using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Pins andy-auth#46 (server-wide PKCE) and andy-auth#122 (S256 is the ONLY
// accepted code-challenge method). The options-level tests assert the
// configured OpenIddict server; the HTTP-surface tests drive /connect/authorize
// and the discovery document through the real pipeline. Both use an Embedded +
// SQLite factory so seeding (which registers the claude-desktop public client)
// runs without Postgres (andy-auth#131), and so OpenIddict accepts plain-HTTP
// requests.
public class PkceEnforcementTests : IDisposable
{
    private readonly string _baseTemp;

    public PkceEnforcementTests()
    {
        _baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-pkce-tests-" + Guid.NewGuid().ToString("N"));
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
    public void OpenIddictServerOptions_RequireProofKeyForCodeExchange_IsTrue()
    {
        using var factory = new CustomWebApplicationFactory();
        using var scope = factory.Services.CreateScope();

        var options = scope.ServiceProvider
            .GetRequiredService<IOptions<OpenIddictServerOptions>>()
            .Value;

        options.RequireProofKeyForCodeExchange.Should().BeTrue(
            "andy-auth#46 closes by enforcing PKCE for every auth-code " +
            "client at the server level — public and confidential alike.");
    }

    [Fact]
    public void OpenIddictServerOptions_CodeChallengeMethods_ContainsOnlyS256()
    {
        using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.UseEnvironment("Development"));
        using var scope = factory.Services.CreateScope();

        var options = scope.ServiceProvider
            .GetRequiredService<IOptions<OpenIddictServerOptions>>()
            .Value;

        options.CodeChallengeMethods.Should().BeEquivalentTo(
            new[] { OpenIddictConstants.CodeChallengeMethods.Sha256 },
            "andy-auth#122: `plain` must be removed so S256 is the only accepted PKCE method.");
        options.CodeChallengeMethods.Should().NotContain(
            OpenIddictConstants.CodeChallengeMethods.Plain);
    }

    [Fact]
    public async Task Discovery_CodeChallengeMethodsSupported_IsExactlyS256()
    {
        using var factory = CreateEmbeddedFactory();
        using var client = HttpClientFor(factory);

        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        var methods = doc.RootElement
            .GetProperty("code_challenge_methods_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        methods.Should().BeEquivalentTo(new[] { "S256" },
            "andy-auth#122: discovery must advertise exactly [\"S256\"], never \"plain\".");
    }

    [Fact]
    public async Task Authorize_WithoutCodeChallenge_IsRejected()
    {
        using var factory = CreateEmbeddedFactory();
        using var client = HttpClientFor(factory);

        var url = "/connect/authorize?" +
                  "client_id=claude-desktop&" +
                  $"redirect_uri={Uri.EscapeDataString("http://127.0.0.1/callback")}&" +
                  "response_type=code&" +
                  "scope=openid%20profile";

        var response = await client.GetAsync(url);

        await AssertInvalidRequestAsync(response,
            "PKCE is mandatory server-wide (#46); an authorization request with no code_challenge must be rejected.");
    }

    [Fact]
    public async Task Authorize_WithPlainCodeChallengeMethod_IsRejected()
    {
        using var factory = CreateEmbeddedFactory();
        using var client = HttpClientFor(factory);

        var verifier = GenerateCodeVerifier();
        // For `plain`, code_challenge == code_verifier. The server must still
        // reject it because `plain` is no longer an accepted method (#122).
        var url = "/connect/authorize?" +
                  "client_id=claude-desktop&" +
                  $"redirect_uri={Uri.EscapeDataString("http://127.0.0.1/callback")}&" +
                  "response_type=code&" +
                  "scope=openid%20profile&" +
                  $"code_challenge={verifier}&" +
                  "code_challenge_method=plain";

        var response = await client.GetAsync(url);

        await AssertInvalidRequestAsync(response,
            "andy-auth#122: code_challenge_method=plain must be rejected once plain is removed.");
    }

    [Fact]
    public async Task Authorize_WithValidS256_IsNotRejected()
    {
        using var factory = CreateEmbeddedFactory();
        using var client = HttpClientFor(factory);

        var verifier = GenerateCodeVerifier();
        var challenge = GenerateCodeChallenge(verifier);
        var url = "/connect/authorize?" +
                  "client_id=claude-desktop&" +
                  $"redirect_uri={Uri.EscapeDataString("http://127.0.0.1/callback")}&" +
                  "response_type=code&" +
                  "scope=openid%20profile&" +
                  $"code_challenge={challenge}&" +
                  "code_challenge_method=S256";

        var response = await client.GetAsync(url);

        // A well-formed PKCE request is accepted by OpenIddict and handed to the
        // app, which challenges the anonymous caller -> 302 to the login page.
        // It must NOT be an OAuth error response.
        response.StatusCode.Should().Be(HttpStatusCode.Found);
        var location = response.Headers.Location?.OriginalString ?? "";
        location.Should().Contain("/Account/Login",
            "a valid S256 request should redirect to sign-in, not fail validation");
        location.Should().NotContain("error=",
            "a valid S256 request must not produce an OAuth error");
    }

    // Accepts either a 400 with `invalid_request` in the body, or a 302 error
    // redirect back to the client's redirect_uri carrying error=invalid_request.
    private static async Task AssertInvalidRequestAsync(HttpResponseMessage response, string because)
    {
        if (response.StatusCode == HttpStatusCode.Found)
        {
            var location = response.Headers.Location?.OriginalString ?? "";
            location.Should().Contain("error=invalid_request", because);
            location.Should().NotContain("/Account/Login",
                "a rejected PKCE request must not reach the sign-in page");
        }
        else
        {
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest, because);
            var body = await response.Content.ReadAsStringAsync();
            body.Should().Contain("invalid_request", because);
        }
    }

    private EnvironmentWebApplicationFactory CreateEmbeddedFactory()
    {
        var modeDir = Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(modeDir);
        return new EnvironmentWebApplicationFactory(
            environmentName: HostEnvironmentExtensions.EmbeddedEnvironmentName,
            dbPath: Path.Combine(modeDir, "andy-auth.sqlite"),
            issuer: "http://localhost:9100/auth/",
            keysPath: Path.Combine(modeDir, "keys"));
    }

    private static HttpClient HttpClientFor(WebApplicationFactory<Program> factory)
    {
        // Embedded disables OpenIddict's transport-security requirement, so the
        // in-memory client speaks http:// (TestServer fakes the scheme).
        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("http://localhost/")
        });
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Base64UrlEncode(bytes);
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncode(challengeBytes);
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
