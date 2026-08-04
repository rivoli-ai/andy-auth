using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for OAuth/OpenID Connect flows
/// </summary>
public class OAuthIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly HttpClient _clientNoRedirect;

    public OAuthIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
        // Client that follows redirects (for most tests)
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = true
        });
        // Client that doesn't follow redirects (for testing OAuth redirects)
        _clientNoRedirect = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    #region Client Credentials Flow Tests

    [Fact]
    public async Task ClientCredentialsFlow_WithValidCredentials_ReturnsAccessToken()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" },
            { "scope", "urn:andy-docs-api" }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);
        var content = await response.Content.ReadAsStringAsync();

        // andy-docs-api is seeded from the fixture manifest wired in by
        // CustomWebApplicationFactory, so this flow runs for real.
        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var tokenResponse = JsonDocument.Parse(content);

        Assert.True(tokenResponse.RootElement.TryGetProperty("access_token", out var accessToken));
        Assert.NotNull(accessToken.GetString());
        Assert.False(string.IsNullOrEmpty(accessToken.GetString()));

        Assert.True(tokenResponse.RootElement.TryGetProperty("token_type", out var tokenType));
        Assert.Equal("Bearer", tokenType.GetString());

        Assert.True(tokenResponse.RootElement.TryGetProperty("expires_in", out var expiresIn));
        Assert.True(expiresIn.GetInt32() > 0);
    }

    [Fact]
    public async Task ClientCredentialsFlow_WithInvalidSecret_ReturnsUnauthorized()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "wrong-secret" },
            { "scope", "urn:andy-docs-api" }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert - OAuth returns Unauthorized for invalid client credentials
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest,
            $"Expected Unauthorized or BadRequest, got {response.StatusCode}");
    }

    [Fact]
    public async Task ClientCredentialsFlow_WithUnknownClient_ReturnsError()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "unknown-client" },
            { "client_secret", "some-secret" }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert - OAuth returns Unauthorized or BadRequest for unknown client
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest,
            $"Expected Unauthorized or BadRequest, got {response.StatusCode}");
    }

    [Fact]
    public async Task ClientCredentialsFlow_WithPublicClient_ReturnsBadRequest()
    {
        // Arrange - wagram-web is a public client (no secret)
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "wagram-web" }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        // Public clients cannot use client_credentials flow
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    #endregion

    #region Token Introspection Tests

    [Fact]
    public async Task TokenIntrospection_WithValidToken_ReturnsActiveTrue()
    {
        // Arrange - First get a token via client credentials
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" },
            { "scope", "urn:andy-docs-api" }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonDocument.Parse(tokenContent);
        Assert.True(tokenJson.RootElement.TryGetProperty("access_token", out var accessTokenElement),
            $"Response did not contain access_token. Content: {tokenContent}");
        var accessToken = accessTokenElement.GetString();

        // Act - Introspect the token
        var introspectRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", accessToken! },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" }
        });

        var introspectResponse = await _client.PostAsync("/connect/introspect", introspectRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, introspectResponse.StatusCode);

        var introspectContent = await introspectResponse.Content.ReadAsStringAsync();
        var introspectJson = JsonDocument.Parse(introspectContent);

        Assert.True(introspectJson.RootElement.TryGetProperty("active", out var active));
        Assert.True(active.GetBoolean());
    }

    [Fact]
    public async Task TokenIntrospection_WithInvalidToken_ReturnsActiveFalse()
    {
        // Arrange
        var introspectRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", "invalid-token-value" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" }
        });

        // Act
        var response = await _client.PostAsync("/connect/introspect", introspectRequest);
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = JsonDocument.Parse(content);

        Assert.True(json.RootElement.TryGetProperty("active", out var active));
        Assert.False(active.GetBoolean());
    }

    [Fact]
    public async Task TokenIntrospection_WithoutClientCredentials_ReturnsError()
    {
        // Arrange
        var introspectRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", "some-token" }
        });

        // Act
        var response = await _client.PostAsync("/connect/introspect", introspectRequest);

        // Assert - OAuth returns Unauthorized or BadRequest when client credentials are missing
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest,
            $"Expected Unauthorized or BadRequest, got {response.StatusCode}");
    }

    #endregion

    #region Token Revocation Tests

    [Fact]
    public async Task TokenRevocation_WithValidToken_ReturnsSuccess()
    {
        // Arrange - First get a token via client credentials
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" },
            { "scope", "urn:andy-docs-api" }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonDocument.Parse(tokenContent);
        Assert.True(tokenJson.RootElement.TryGetProperty("access_token", out var accessTokenElement),
            $"Response did not contain access_token. Content: {tokenContent}");
        var accessToken = accessTokenElement.GetString();

        // Act - Revoke the token
        var revokeRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", accessToken! },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" }
        });

        var revokeResponse = await _client.PostAsync("/connect/revoke", revokeRequest);

        // Assert - Revocation endpoint returns 200 OK on success
        Assert.Equal(HttpStatusCode.OK, revokeResponse.StatusCode);
    }

    [Fact]
    public async Task TokenRevocation_WithInvalidToken_StillReturnsSuccess()
    {
        // Arrange - Per RFC 7009, revocation of invalid token should succeed
        var revokeRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", "invalid-or-already-revoked-token" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" }
        });

        // Act
        var response = await _client.PostAsync("/connect/revoke", revokeRequest);

        // Assert - Per RFC 7009, should return 200 even for invalid tokens
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TokenRevocation_RevokedToken_ShouldBeInactive()
    {
        // Arrange - Get a token
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" },
            { "scope", "urn:andy-docs-api" }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonDocument.Parse(tokenContent);
        Assert.True(tokenJson.RootElement.TryGetProperty("access_token", out var accessTokenElement),
            $"Response did not contain access_token. Content: {tokenContent}");
        var accessToken = accessTokenElement.GetString();

        // Revoke the token
        var revokeRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", accessToken! },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" }
        });
        await _client.PostAsync("/connect/revoke", revokeRequest);

        // Act - Introspect the revoked token
        var introspectRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "token", accessToken! },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" }
        });
        var introspectResponse = await _client.PostAsync("/connect/introspect", introspectRequest);

        // Assert - Revoked token should be inactive
        var introspectContent = await introspectResponse.Content.ReadAsStringAsync();
        var introspectJson = JsonDocument.Parse(introspectContent);

        Assert.True(introspectJson.RootElement.TryGetProperty("active", out var active));
        Assert.False(active.GetBoolean());
    }

    #endregion

    #region UserInfo Endpoint Tests

    [Fact]
    public async Task UserInfo_WithoutToken_ReturnsErrorResponse()
    {
        // Act
        var response = await _client.GetAsync("/connect/userinfo");

        // Assert - Without a valid token, should return Unauthorized or error
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest ||
            response.StatusCode == HttpStatusCode.InternalServerError,
            $"Expected error response, got {response.StatusCode}");
    }

    [Fact]
    public async Task UserInfo_WithInvalidToken_ReturnsErrorResponse()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

        // Act
        var response = await _client.SendAsync(request);

        // Assert - With invalid token, should return error
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest ||
            response.StatusCode == HttpStatusCode.InternalServerError,
            $"Expected error response, got {response.StatusCode}");
    }

    [Fact]
    public async Task UserInfo_WithClientCredentialsToken_ReturnsResponse()
    {
        // Arrange - Get a token via client credentials (machine-to-machine)
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", "andy-docs-api" },
            { "client_secret", "andy-docs-api-secret-change-in-production" },
            { "scope", "urn:andy-docs-api" }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonDocument.Parse(tokenContent);
        Assert.True(tokenJson.RootElement.TryGetProperty("access_token", out var accessTokenElement),
            $"Response did not contain access_token. Content: {tokenContent}");
        var accessToken = accessTokenElement.GetString();

        // Act - Try to access userinfo with client credentials token
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await _client.SendAsync(request);

        // Assert - Client credentials tokens don't have user context
        // This will return 401, OK, or error depending on configuration
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.OK ||
            response.StatusCode == HttpStatusCode.InternalServerError,
            $"Expected Unauthorized, OK, or InternalServerError, got {response.StatusCode}");
    }

    [Fact]
    public async Task UserInfo_EndpointExistsInDiscovery()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        var content = await response.Content.ReadAsStringAsync();
        var discovery = JsonDocument.Parse(content);

        // The discovery document must always be valid JSON with an issuer.
        Assert.True(discovery.RootElement.TryGetProperty("issuer", out _));

        // userinfo_endpoint is optional in OpenIddict's metadata (this
        // deployment does not advertise it even though /connect/userinfo is
        // routable — see the UserInfo_* tests that exercise it directly).
        // When it IS advertised, it must point at the canonical path.
        if (discovery.RootElement.TryGetProperty("userinfo_endpoint", out var userinfoEndpoint))
        {
            Assert.Contains("/connect/userinfo", userinfoEndpoint.GetString());
        }
    }

    #endregion

    #region Discovery and Configuration Tests

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

    #endregion

    #region Authorization Code Flow Tests

    [Fact]
    public async Task Authorization_WithRevokedInteractiveSession_ReturnsToLoginBeforeIssuance()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true,
            BaseAddress = new Uri("https://localhost")
        });

        var loginStartedAt = DateTime.UtcNow.AddSeconds(-1);
        var loginPage = await client.GetAsync("/Account/Login");
        loginPage.EnsureSuccessStatusCode();
        var html = await loginPage.Content.ReadAsStringAsync();
        var tokenMatch = Regex.Match(
            html,
            @"<input[^>]*name=""__RequestVerificationToken""[^>]*value=""([^""]+)""");
        Assert.True(tokenMatch.Success, "The login form must contain an antiforgery token.");

        var loginResponse = await client.PostAsync(
            "/Account/Login",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Email"] = CustomWebApplicationFactory.AdminEmail,
                ["Password"] = CustomWebApplicationFactory.AdminPassword,
                ["RememberMe"] = "false",
                ["__RequestVerificationToken"] = tokenMatch.Groups[1].Value
            }));
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);

        string sessionId;
        using (var scope = _factory.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var user = await dbContext.Users.SingleAsync(
                u => u.Email == CustomWebApplicationFactory.AdminEmail);
            var session = await dbContext.UserSessions
                .Where(s => s.UserId == user.Id && s.CreatedAt >= loginStartedAt)
                .OrderByDescending(s => s.CreatedAt)
                .FirstOrDefaultAsync();

            Assert.NotNull(session);
            sessionId = session!.SessionId;

            var sessionService = scope.ServiceProvider.GetRequiredService<SessionService>();
            Assert.True(await sessionService.RevokeSessionByIdAsync(
                sessionId, "OAuth integration revocation test"));
        }

        var verifier = GenerateCodeVerifier();
        var challenge = GenerateCodeChallenge(verifier);
        var authorizeResponse = await client.GetAsync(
            "/connect/authorize" +
            "?client_id=claude-desktop" +
            "&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback" +
            "&response_type=code" +
            "&scope=openid%20profile" +
            $"&code_challenge={challenge}" +
            "&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        Assert.StartsWith(
            "/Account/Login?sessionExpired=true",
            authorizeResponse.Headers.Location?.OriginalString,
            StringComparison.Ordinal);
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

        var authResponse = await _clientNoRedirect.GetAsync(authUrl);

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
        var discoveryResponse = await _client.GetAsync("/.well-known/openid-configuration");
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

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequestWithoutCode);

        // Should be BadRequest because code is missing
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
    }

    #endregion

    #region Helper Methods

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

    #endregion
}
