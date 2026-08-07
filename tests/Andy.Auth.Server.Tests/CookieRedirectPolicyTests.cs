using System.Net;
using System.Security.Cryptography;
using System.Text;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Pins the .NET 10 cookie-redirect behaviour of the OAuth authorization
// endpoint.
//
// .NET 10 stopped redirecting unauthenticated cookie challenges to LoginPath
// for endpoints carrying IDisableCookieRedirectMetadata — which [ApiController]
// implements — and returns 401 with a Location header instead:
// https://learn.microsoft.com/aspnet/core/breaking-changes/10/cookie-authentication-api-endpoints
//
// AuthorizationController is an [ApiController], so /connect/authorize was
// caught by that rule even though a real browser drives it. A 401 there breaks
// interactive sign-in for every registered client, and only the status code
// changes — the Location header stays correct — so an assertion that checks the
// redirect target alone would not catch a regression. Assert the status code.
//
// The negative control lives in HealthCheckTests.ProtectedEndpoint_ChallengesAnonymousRequest:
// /Session is not [ApiController], keeps the framework default, and must still
// redirect. Between the two, both sides of the policy are covered.
public class CookieRedirectPolicyTests : IDisposable
{
    private readonly string _baseTemp;

    public CookieRedirectPolicyTests()
    {
        _baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-cookie-redirect-tests-" + Guid.NewGuid().ToString("N"));
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
    public async Task Authorize_AnonymousRequest_RedirectsToSignInRatherThan401()
    {
        using var factory = CreateEmbeddedFactory();
        using var client = HttpClientFor(factory);

        var response = await client.GetAsync(AuthorizeUrl());

        response.StatusCode.Should().Be(
            HttpStatusCode.Found,
            "an anonymous browser hitting /connect/authorize must be redirected to " +
            "sign-in; a 401 (the .NET 10 default for [ApiController] endpoints) " +
            "breaks the interactive OAuth flow for every client");

        var location = response.Headers.Location?.OriginalString ?? "";
        location.Should().Contain("/Account/Login");
        location.Should().Contain(
            Uri.EscapeDataString("/connect/authorize"),
            "the challenge must return the caller to the authorization request");
    }

    private static string AuthorizeUrl()
    {
        var challenge = GenerateCodeChallenge(GenerateCodeVerifier());
        return "/connect/authorize?" +
               "client_id=claude-desktop&" +
               $"redirect_uri={Uri.EscapeDataString("http://127.0.0.1/callback")}&" +
               "response_type=code&" +
               "scope=openid%20profile&" +
               $"code_challenge={challenge}&" +
               "code_challenge_method=S256";
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

    private static HttpClient HttpClientFor(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("http://localhost/")
        });

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
        return Base64UrlEncode(sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier)));
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
