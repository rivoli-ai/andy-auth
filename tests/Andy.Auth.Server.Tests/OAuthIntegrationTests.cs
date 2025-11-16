using System.Net;
using System.Text.Json;
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
}
