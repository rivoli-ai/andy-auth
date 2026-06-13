using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for the anonymous /health liveness endpoint
/// (rivoli-ai/andy-auth#116). The endpoint exists for parity with sibling
/// andy-* services so Conductor's UnifiedProxy can probe 9100/auth/health
/// (the /auth prefix is stripped before it reaches andy-auth) uniformly with
/// every other service. Liveness must be anonymous and must not touch the DB,
/// OpenIddict, or the session store.
/// </summary>
public class HealthCheckTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;

    public HealthCheckTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Health_ReturnsOk()
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Health_BodyHasHealthyStatusAndParseableTimestamp()
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");
        var json = await response.Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("healthy", root.GetProperty("status").GetString());
        Assert.Equal("andy-auth", root.GetProperty("service").GetString());

        var timestamp = root.GetProperty("timestamp").GetString();
        Assert.True(
            DateTime.TryParse(timestamp, out _),
            $"timestamp '{timestamp}' should be parseable");
    }

    [Fact]
    public async Task Health_SucceedsWithoutAuthorizationHeader()
    {
        // The endpoint sits behind UseAuthentication()/UseAuthorization() and
        // must answer without any credentials (the Conductor probe sends none).
        using var client = _factory.CreateClient();
        Assert.Null(client.DefaultRequestHeaders.Authorization);

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Health_DoesNotIssueSessionCookie()
    {
        // /health is in the SessionTrackingMiddleware bypass set
        // (SessionTrackingMiddleware.cs:21). Guard that bypass entry against
        // regression: the probe must not create or mutate a session, so no
        // Set-Cookie should be emitted.
        // https BaseAddress avoids UseHttpsRedirection's 307 (TestServer fakes
        // both schemes); without it a non-redirecting client never reaches the
        // endpoint. Same pattern as CrossModeDiscoveryTests.
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost/")
        });

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(
            response.Headers.Contains("Set-Cookie"),
            "/health must not issue a session cookie");
    }

    [Fact]
    public async Task ProtectedEndpoint_ChallengesAnonymousRequest()
    {
        // Negative control: proves the test host has auth enabled, so the
        // /health tests above pass because of .AllowAnonymous() and not because
        // authentication is globally off. SessionController is
        // [Authorize(Identity.Application)], so an anonymous request is
        // challenged (302 redirect to the login page) rather than served 200 —
        // and the cookie-challenge path touches neither the DB nor OpenIddict,
        // so it is reliable even when the test host has no database.
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost/")
        });

        var response = await client.GetAsync("/Session");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Account/Login", response.Headers.Location?.OriginalString ?? "");
    }
}
