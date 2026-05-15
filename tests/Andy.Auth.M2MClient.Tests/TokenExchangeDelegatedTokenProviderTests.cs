// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Andy.Auth.M2MClient.Tests;

/// <summary>
/// Tests for the RFC 8693 OBO token provider. Mirrors the patterns in
/// <c>ClientCredentialsTokenProviderTests</c> — same stub HTTP handler,
/// fake time provider, single-client factory. Drives Epic IDP
/// (rivoli-ai/conductor#1246).
/// </summary>
public sealed class TokenExchangeDelegatedTokenProviderTests
{
    private const string EnvVar = "ANDY_AUTH_M2M_TESTS_SECRET";
    private const string ClientId = "andy-containers-api";
    private const string TokenEndpoint = "http://andy-auth.test/connect/token";
    private const string SubjectToken = "header.payload.signature";
    private const string Audience = "urn:andy-models-api";

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_PostsExpectedFormFields()
    {
        string? observed = null;
        var handler = new StubHandler(async (req, ct) =>
        {
            observed = await req.Content!.ReadAsStringAsync(ct);
            return TokenResponse("delegated-jwt", expiresIn: 900);
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var token = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);

        Assert.Equal("delegated-jwt", token);
        Assert.NotNull(observed);
        Assert.Contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange", observed);
        Assert.Contains($"client_id={ClientId}", observed);
        Assert.Contains("subject_token=header.payload.signature", observed);
        Assert.Contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token", observed);
        Assert.Contains("resource=urn%3Aandy-models-api", observed);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_CachesPerSubjectAudiencePair()
    {
        var calls = 0;
        var handler = new StubHandler((req, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse($"token-{calls}", expiresIn: 3600));
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var first = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);
        var second = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);

        Assert.Equal("token-1", first);
        Assert.Equal("token-1", second);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_SeparateCacheForDifferentAudience()
    {
        var calls = 0;
        var handler = new StubHandler((req, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse($"token-{calls}", expiresIn: 3600));
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var modelsToken = await provider.GetTokenOnBehalfOfAsync(SubjectToken, "urn:andy-models-api");
        var settingsToken = await provider.GetTokenOnBehalfOfAsync(SubjectToken, "urn:andy-settings-api");
        var modelsAgain = await provider.GetTokenOnBehalfOfAsync(SubjectToken, "urn:andy-models-api");

        Assert.Equal("token-1", modelsToken);
        Assert.Equal("token-2", settingsToken);
        Assert.Equal("token-1", modelsAgain);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_SeparateCacheForDifferentSubject()
    {
        var calls = 0;
        var handler = new StubHandler((req, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse($"token-{calls}", expiresIn: 3600));
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var userA = await provider.GetTokenOnBehalfOfAsync("user-a.jwt.sig", Audience);
        var userB = await provider.GetTokenOnBehalfOfAsync("user-b.jwt.sig", Audience);

        Assert.Equal("token-1", userA);
        Assert.Equal("token-2", userB);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_RefreshesNearExpiry()
    {
        var calls = 0;
        var handler = new StubHandler((req, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse(calls == 1 ? "first" : "second", expiresIn: 120));
        });
        var time = new FakeTimeProvider();
        using var provider = NewProvider(handler, time);

        var t1 = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);
        time.Advance(TimeSpan.FromSeconds(59));
        var t2 = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);
        time.Advance(TimeSpan.FromSeconds(2));
        var t3 = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);

        Assert.Equal("first", t1);
        Assert.Equal("first", t2);
        Assert.Equal("second", t3);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_CoalescesConcurrentFirstCalls()
    {
        var calls = 0;
        var release = new TaskCompletionSource();
        var handler = new StubHandler(async (_, _) =>
        {
            Interlocked.Increment(ref calls);
            await release.Task.ConfigureAwait(false);
            return TokenResponse("shared", expiresIn: 3600);
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var t1 = provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);
        var t2 = provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);
        var t3 = provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);
        release.SetResult();
        var results = await Task.WhenAll(t1, t2, t3);

        Assert.All(results, r => Assert.Equal("shared", r));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_ThrowsServiceTokenException_OnRejection()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent(
                    "{\"error\":\"unauthorized_client\",\"error_description\":\"the actor is not permitted to exchange tokens for this audience.\"}",
                    Encoding.UTF8, "application/json"),
            }));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience));
        Assert.Contains("[M2M-OBO-REJECTED]", ex.Message);
        Assert.Contains("403", ex.Message);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_ThrowsServiceTokenException_OnUnreachable()
    {
        var handler = new StubHandler((_, _) =>
            throw new HttpRequestException("Connection refused"));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience));
        Assert.Contains("[M2M-OBO-UNREACHABLE]", ex.Message);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_ThrowsServiceTokenException_OnEmptyAccessToken()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"token_type\":\"Bearer\",\"expires_in\":900}",
                    Encoding.UTF8, "application/json"),
            }));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience));
        Assert.Contains("[M2M-OBO-EMPTY]", ex.Message);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_RejectsEmptySubjectToken()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(TokenResponse("x", 60)));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenOnBehalfOfAsync("", Audience));
        Assert.Contains("[M2M-OBO-NOSUBJECT]", ex.Message);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_RejectsEmptyAudience()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(TokenResponse("x", 60)));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenOnBehalfOfAsync(SubjectToken, ""));
        Assert.Contains("[M2M-OBO-NOAUDIENCE]", ex.Message);
    }

    [Fact]
    public async Task GetTokenOnBehalfOfAsync_RefetchesAfterFailure()
    {
        // A previous rejection should NOT leave a stale cache entry —
        // the next call must hit the wire again.
        var calls = 0;
        var handler = new StubHandler((_, _) =>
        {
            calls++;
            if (calls == 1)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("{\"error\":\"unauthorized_client\"}",
                        Encoding.UTF8, "application/json"),
                });
            }
            return Task.FromResult(TokenResponse("recovered", expiresIn: 3600));
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience));
        var second = await provider.GetTokenOnBehalfOfAsync(SubjectToken, Audience);

        Assert.Equal("recovered", second);
        Assert.Equal(2, calls);
    }

    // ------- helpers (shape-identical to ClientCredentialsTokenProviderTests) -------

    private static TokenExchangeDelegatedTokenProvider NewProvider(
        HttpMessageHandler handler, TimeProvider time)
    {
        var http = new HttpClient(handler);
        var factory = new SingleClientFactory(http);
        var options = Options.Create(new AndyAuthM2MOptions
        {
            TokenEndpoint = TokenEndpoint,
            ClientId = ClientId,
            ClientSecretEnvVar = EnvVar,
        });
        return new TokenExchangeDelegatedTokenProvider(
            factory, options, time, NullLogger<TokenExchangeDelegatedTokenProvider>.Instance);
    }

    private static HttpResponseMessage TokenResponse(string accessToken, int expiresIn)
    {
        // Note: only the first segment is interpolated, so the leading
        // `{{` collapses to `{`. The trailing literal `}` must be a
        // single brace because the second string is not interpolated.
        var json =
            $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"Bearer\",\"expires_in\":{expiresIn}," +
            "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private sealed class SingleClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleClientFactory(HttpClient client) { _client = client; }
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;
        public StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        {
            _respond = respond;
        }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => _respond(request, cancellationToken);
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 5, 13, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
