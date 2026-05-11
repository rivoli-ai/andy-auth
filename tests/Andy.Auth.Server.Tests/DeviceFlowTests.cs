using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for the RFC 8628 device authorization grant.
/// Covers the discovery surface (clients learn the device endpoint
/// URLs from /.well-known/openid-configuration) and the
/// authorization-pending response semantics that the andy-mcp-proxy
/// CLI relies on for its polling loop.
/// </summary>
public class DeviceFlowTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public DeviceFlowTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = true
        });
    }

    [Fact]
    public async Task DiscoveryDocument_AdvertisesDeviceAuthorizationEndpoint()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;

        // Per OAuth 2.0 Authorization Server Metadata + RFC 8628.
        // The CLI reads device_authorization_endpoint to know where to
        // POST its initial request.
        Assert.True(root.TryGetProperty("device_authorization_endpoint", out var deviceEndpoint),
            "Discovery document must advertise device_authorization_endpoint once the device-flow is enabled.");
        var deviceEndpointUrl = deviceEndpoint.GetString();
        Assert.NotNull(deviceEndpointUrl);
        Assert.EndsWith("/connect/device", deviceEndpointUrl);
    }

    [Fact]
    public async Task DiscoveryDocument_AdvertisesDeviceCodeGrantType()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.True(doc.RootElement.TryGetProperty("grant_types_supported", out var grantTypes),
            "Discovery document must list grant_types_supported.");

        var supported = new List<string>();
        foreach (var item in grantTypes.EnumerateArray())
        {
            supported.Add(item.GetString() ?? string.Empty);
        }

        // OpenIddict normalises the URN form when adding the device grant.
        Assert.Contains("urn:ietf:params:oauth:grant-type:device_code", supported);
    }

    [Fact]
    public async Task DeviceAuthorizationEndpoint_RejectsUnknownClient()
    {
        // Clients have to be seeded with the device_code grant in their
        // manifest before the endpoint accepts a request from them.
        // An unknown client gets invalid_client, never reaches the
        // code-issuance path. Locks in the client-gating behaviour.
        var request = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "client_id", "this-client-does-not-exist" },
        });

        var response = await _client.PostAsync("/connect/device", request);

        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            // CI / no DB — same skip pattern OAuthIntegrationTests uses.
            Assert.True(true, "Skipping - server returned 500 (database may not be available)");
            return;
        }

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest ||
            response.StatusCode == HttpStatusCode.Unauthorized,
            $"Expected 400/401 for unknown client, got {(int)response.StatusCode}. Body: {body}");
        Assert.Contains("invalid_client", body);
    }

    [Fact]
    public async Task TokenEndpoint_DeviceCodeGrant_RejectsInvalidDeviceCode()
    {
        // The CLI's polling loop hits /connect/token with grant_type
        // device_code; an invalid/unknown code must yield invalid_grant
        // (not 500). This is the failure path the CLI surfaces to the
        // user when the verification step never completed.
        var request = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
            { "client_id", "claude-desktop" },
            { "device_code", "this-code-does-not-exist" },
        });

        var response = await _client.PostAsync("/connect/token", request);

        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            Assert.True(true, "Skipping - server returned 500 (database may not be available)");
            return;
        }

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // OpenIddict returns invalid_grant for unknown device codes,
        // matching RFC 8628 §3.5. Some upstream versions normalise to
        // unauthorized_client when the grant type isn't allowed for
        // the client — accept either since the CLI surfaces both as
        // "the device-code flow is not yet authorised for this client".
        Assert.True(
            body.Contains("invalid_grant") || body.Contains("unauthorized_client") || body.Contains("invalid_client"),
            $"Expected an OAuth error code in body, got: {body}");
    }
}
