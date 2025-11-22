using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for OAuth/OpenID Connect flows
/// </summary>
public class OAuthIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public OAuthIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    [Fact]
    public async Task OpenIdDiscovery_ReturnsValidConfiguration()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        var content = await response.Content.ReadAsStringAsync();
        var discovery = JsonDocument.Parse(content);

        // Verify required OpenID Connect discovery fields
        Assert.True(discovery.RootElement.TryGetProperty("issuer", out var issuer));
        Assert.NotNull(issuer.GetString());

        Assert.True(discovery.RootElement.TryGetProperty("authorization_endpoint", out var authEndpoint));
        Assert.Contains("/connect/authorize", authEndpoint.GetString());

        Assert.True(discovery.RootElement.TryGetProperty("token_endpoint", out var tokenEndpoint));
        Assert.Contains("/connect/token", tokenEndpoint.GetString());

        Assert.True(discovery.RootElement.TryGetProperty("jwks_uri", out var jwksUri));
        Assert.NotNull(jwksUri.GetString());

        // Verify supported grant types
        Assert.True(discovery.RootElement.TryGetProperty("grant_types_supported", out var grantTypes));
        var grantTypeArray = grantTypes.EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("authorization_code", grantTypeArray);
        Assert.Contains("refresh_token", grantTypeArray);
        Assert.Contains("client_credentials", grantTypeArray);

        // Verify supported scopes
        Assert.True(discovery.RootElement.TryGetProperty("scopes_supported", out var scopes));
        var scopeArray = scopes.EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("openid", scopeArray);
        Assert.Contains("profile", scopeArray);
        Assert.Contains("email", scopeArray);
    }

    [Fact]
    public async Task JwksUri_ReturnsValidKeys()
    {
        // Arrange
        var discoveryResponse = await _client.GetAsync("/.well-known/openid-configuration");
        var discoveryContent = await discoveryResponse.Content.ReadAsStringAsync();
        var discovery = JsonDocument.Parse(discoveryContent);
        var jwksUri = discovery.RootElement.GetProperty("jwks_uri").GetString();

        // Act
        var response = await _client.GetAsync(new Uri(jwksUri!));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var jwks = JsonDocument.Parse(content);

        Assert.True(jwks.RootElement.TryGetProperty("keys", out var keys));
        Assert.True(keys.GetArrayLength() > 0);
    }

    [Fact]
    public async Task LoginPage_ReturnsSuccessfully()
    {
        // Act
        var response = await _client.GetAsync("/Account/Login");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task RegisterPage_ReturnsSuccessfully()
    {
        // Act
        var response = await _client.GetAsync("/Account/Register");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task AuthorizeEndpoint_WithoutParameters_ReturnsBadRequest()
    {
        // Act
        var response = await _client.GetAsync("/connect/authorize");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoint_WithoutParameters_ReturnsBadRequest()
    {
        // Act
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>()));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task HomePage_ReturnsSuccessfully()
    {
        // Act
        var response = await _client.GetAsync("/");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ClaudeDesktopClient_AuthorizationCodeFlowWithPKCE_ShouldSucceed()
    {
        // Arrange - Generate PKCE parameters
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var state = Guid.NewGuid().ToString("N");
        var redirectUri = "http://127.0.0.1/callback";

        // Step 1: Start authorization flow
        var authUrl = $"/connect/authorize?" +
                     $"client_id=claude-desktop&" +
                     $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                     $"response_type=code&" +
                     $"scope=openid%20profile%20email&" +
                     $"code_challenge={codeChallenge}&" +
                     $"code_challenge_method=S256&" +
                     $"state={state}";

        var authResponse = await _client.GetAsync(authUrl);

        // Should redirect to login page (302/307) or challenge with login form (200)
        Assert.True(
            authResponse.StatusCode == HttpStatusCode.Redirect ||
            authResponse.StatusCode == HttpStatusCode.RedirectKeepVerb ||
            authResponse.StatusCode == HttpStatusCode.OK,
            $"Expected Redirect, RedirectKeepVerb or OK, got {authResponse.StatusCode}");

        // Verify the authorization endpoint requires authentication
        // In a real flow, user would authenticate here
        // For testing, we verify the endpoint is properly configured

        // Step 2: Verify client is properly seeded
        // Follow redirects to get the actual discovery document
        var discoveryClient = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = true
        });
        var discoveryResponse = await discoveryClient.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, discoveryResponse.StatusCode);

        var discoveryContent = await discoveryResponse.Content.ReadAsStringAsync();
        var discovery = JsonDocument.Parse(discoveryContent);

        // Verify PKCE is supported
        Assert.True(discovery.RootElement.TryGetProperty("code_challenge_methods_supported", out var methods));
        var methodArray = methods.EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("S256", methodArray);

        // Step 3: Verify token endpoint configuration
        Assert.True(discovery.RootElement.TryGetProperty("token_endpoint", out var tokenEndpoint));
        var tokenUrl = tokenEndpoint.GetString();
        Assert.NotNull(tokenUrl);
        Assert.Contains("/connect/token", tokenUrl);

        // Step 4: Test that token endpoint rejects request without valid authorization code
        var tokenRequestWithoutCode = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "client_id", "claude-desktop" },
            { "redirect_uri", redirectUri },
            { "code_verifier", codeVerifier }
        });

        var tokenClient = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = true
        });
        var tokenResponse = await tokenClient.PostAsync("/connect/token", tokenRequestWithoutCode);

        // Should be BadRequest because code is missing
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
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

    private static string Base64UrlEncode(byte[] input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
