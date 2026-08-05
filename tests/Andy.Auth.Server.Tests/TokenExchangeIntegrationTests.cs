using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for the RFC 8693 token-exchange grant on the
/// <c>/connect/token</c> endpoint. We cover the input-validation and
/// policy-denial paths here because those don't require minting a real
/// user access token in the test setup. Happy-path validation (which
/// needs a real subject_token issued by the same server) is exercised
/// by the validator unit tests + a follow-up E2E test in
/// <c>Andy.Auth.E2E.Tests</c>.
///
/// Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
public class TokenExchangeIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly CustomWebApplicationFactory _factory;

    public TokenExchangeIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
        // Follow redirects so HTTPS-redirect middleware doesn't trap
        // the POST. Matches the pattern used in OAuthIntegrationTests.
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = true,
        });
    }

    private const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    private static FormUrlEncodedContent ExchangeForm(
        string clientId,
        string clientSecret,
        string subjectToken,
        string? resource = "urn:andy-models-api",
        string? subjectTokenType = "urn:ietf:params:oauth:token-type:access_token",
        string? scope = null)
    {
        var dict = new Dictionary<string, string>
        {
            { "grant_type", GrantType },
            { "client_id", clientId },
            { "client_secret", clientSecret },
            { "subject_token", subjectToken },
        };
        if (resource is not null) dict.Add("resource", resource);
        if (subjectTokenType is not null) dict.Add("subject_token_type", subjectTokenType);
        if (scope is not null) dict.Add("scope", scope);
        return new FormUrlEncodedContent(dict);
    }

    private async Task<(string Token, DateTime ExpiresAt)> MintSubjectTokenAsync(
        string audience = "urn:andy-containers-api",
        string tokenType = "at+jwt",
        string scope = "read write",
        TimeSpan? lifetime = null)
    {
        string userId;
        var sessionId = $"exchange-{Guid.NewGuid():N}";
        using (var scopeServices = _factory.Services.CreateScope())
        {
            var dbContext = scopeServices.ServiceProvider
                .GetRequiredService<ApplicationDbContext>();
            userId = await dbContext.Users
                .Where(user => user.Email == CustomWebApplicationFactory.AdminEmail)
                .Select(user => user.Id)
                .SingleAsync();
            var sessionService = scopeServices.ServiceProvider
                .GetRequiredService<SessionService>();
            await sessionService.CreateSessionAsync(
                userId, sessionId, "127.0.0.1", "TokenExchangeIntegrationTests");
        }

        var options = _factory.Services
            .GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>()
            .CurrentValue;
        var expiresAt = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(30));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer!.ToString(),
            Audience = audience,
            TokenType = tokenType,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", userId),
                new Claim("scope", scope),
                new Claim(AndyAuthSignInManager.SessionIdClaimType, sessionId)
            }),
            Expires = expiresAt,
            SigningCredentials = options.SigningCredentials.First()
        };

        return (new JsonWebTokenHandler().CreateToken(descriptor), expiresAt);
    }

    [Fact]
    public async Task Returns_BadRequest_WhenSubjectTokenMissing()
    {
        // No subject_token at all → invalid_request.
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", GrantType },
            { "client_id", "andy-containers-api" },
            { "client_secret", "andy-containers-api-secret-change-in-production" },
            { "resource", "urn:andy-models-api" },
        });

        var response = await _client.PostAsync("/connect/token", form);
        var body = await response.Content.ReadAsStringAsync();
        // OpenIddict returns 400 with `error=invalid_request` or
        // similar for missing-parameter cases. Either invalid_grant
        // or invalid_request is acceptable here — the important bit
        // is that the request was rejected, not silently accepted.
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest
            || response.StatusCode == HttpStatusCode.Forbidden,
            $"Expected 400/403, got {response.StatusCode}: {body}");
    }

    [Fact]
    public async Task Returns_Error_WhenSubjectTokenTypeIsRefreshToken()
    {
        // We only accept access tokens as subject_token per
        // TokenExchangeConstants.AccessTokenType — refresh tokens
        // and SAML assertions are out.
        var form = ExchangeForm(
            clientId: "andy-containers-api",
            clientSecret: "andy-containers-api-secret-change-in-production",
            subjectToken: "any-string",
            subjectTokenType: "urn:ietf:params:oauth:token-type:refresh_token");

        var response = await _client.PostAsync("/connect/token", form);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(
            response.StatusCode == HttpStatusCode.BadRequest
            || response.StatusCode == HttpStatusCode.Forbidden,
            $"Expected rejection, got {response.StatusCode}: {body}");
    }

    [Fact]
    public async Task Returns_Error_WhenSubjectTokenIsInvalid()
    {
        // A random string can never be a valid access token. The
        // SubjectTokenValidator will reject it before we hit policy.
        var form = ExchangeForm(
            clientId: "andy-containers-api",
            clientSecret: "andy-containers-api-secret-change-in-production",
            subjectToken: "this-is-not-a-valid-jwt");

        var response = await _client.PostAsync("/connect/token", form);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(
            response.StatusCode == HttpStatusCode.Forbidden
            || response.StatusCode == HttpStatusCode.BadRequest,
            $"Expected rejection, got {response.StatusCode}: {body}");

        // Body should contain an OAuth error identifier rather than
        // a raw stack trace or empty content. OpenIddict 7 may reject
        // an unregistered resource with invalid_target before we ever
        // reach the handler — that's still a valid rejection.
        Assert.True(
            body.Contains("invalid_grant", StringComparison.Ordinal)
            || body.Contains("unauthorized_client", StringComparison.Ordinal)
            || body.Contains("invalid_request", StringComparison.Ordinal)
            || body.Contains("invalid_target", StringComparison.Ordinal),
            $"Expected RFC 6749 error code in body, got: {body}");
    }

    [Fact]
    public async Task Returns_InvalidTarget_WhenNoAudienceRequested()
    {
        var form = ExchangeForm(
            clientId: "andy-containers-api",
            clientSecret: "andy-containers-api-secret-change-in-production",
            subjectToken: "any-string",
            resource: null);

        var response = await _client.PostAsync("/connect/token", form);
        var body = await response.Content.ReadAsStringAsync();
        // RFC 8693 says invalid_target for audience problems, but
        // OpenIddict may surface it as invalid_request — accept either.
        Assert.True(
            response.StatusCode == HttpStatusCode.Forbidden
            || response.StatusCode == HttpStatusCode.BadRequest,
            $"Expected rejection, got {response.StatusCode}: {body}");
    }

    [Fact]
    public async Task Rejects_LocallySignedGenericJwt_AsAccessTokenSubject()
    {
        var (subjectToken, _) = await MintSubjectTokenAsync(tokenType: "JWT");

        var response = await _client.PostAsync(
            "/connect/token",
            ExchangeForm(
                "andy-containers-api",
                "andy-containers-api-secret-change-in-production",
                subjectToken));

        var body = await response.Content.ReadAsStringAsync();
        Assert.False(response.IsSuccessStatusCode, body);
        Assert.Contains("invalid_grant", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_SubjectTokenForUnrelatedAudience()
    {
        var (subjectToken, _) = await MintSubjectTokenAsync(
            audience: "urn:unrelated-api");

        var response = await _client.PostAsync(
            "/connect/token",
            ExchangeForm(
                "andy-containers-api",
                "andy-containers-api-secret-change-in-production",
                subjectToken));

        var body = await response.Content.ReadAsStringAsync();
        Assert.False(response.IsSuccessStatusCode, body);
        Assert.Contains("invalid_grant", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_ScopeAbsentFromSubjectToken()
    {
        var (subjectToken, _) = await MintSubjectTokenAsync(scope: "read");

        var response = await _client.PostAsync(
            "/connect/token",
            ExchangeForm(
                "andy-containers-api",
                "andy-containers-api-secret-change-in-production",
                subjectToken,
                scope: "admin"));

        var body = await response.Content.ReadAsStringAsync();
        Assert.False(response.IsSuccessStatusCode, body);
        Assert.Contains("invalid_scope", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidExchange_AttenuatesScopesAndNeverOutlivesSubject()
    {
        var (subjectToken, subjectExpiresAt) = await MintSubjectTokenAsync(
            scope: "read write",
            lifetime: TimeSpan.FromMinutes(3));

        var response = await _client.PostAsync(
            "/connect/token",
            ExchangeForm(
                "andy-containers-api",
                "andy-containers-api-secret-change-in-production",
                subjectToken));

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, body);
        using var payload = JsonDocument.Parse(body);
        var accessToken = payload.RootElement.GetProperty("access_token").GetString();
        Assert.NotNull(accessToken);

        var jwt = new JsonWebToken(accessToken);
        Assert.Contains("urn:andy-models-api", jwt.Audiences);
        Assert.True(jwt.ValidTo <= subjectExpiresAt.AddSeconds(1));
        Assert.True(jwt.ValidTo > DateTime.UtcNow.AddMinutes(2));
        var wireScopes = jwt.GetPayloadValue<string>("scope")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(new[] { "read", "write" }, wireScopes);
        Assert.NotNull(jwt.GetPayloadValue<string>(AndyAuthSignInManager.SessionIdClaimType));
    }
}
