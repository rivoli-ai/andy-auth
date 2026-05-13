// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Net;
using System.Text;
using Andy.Auth.M2MClient;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Andy.Auth.M2MClient.Tests;

// Tests cover the conductor#990 consumer-side provider semantics:
// cache-then-refresh, concurrent coalescence, fail-fast on transport /
// credential errors, the dev-fallback secret resolution that mirrors
// andy-auth's DbSeeder, and the on-demand refresh path used by
// ServiceBearerHandler's 401 retry.
public sealed class ClientCredentialsTokenProviderTests
{
    private const string EnvVar = "ANDY_AUTH_M2M_TESTS_SECRET";
    private const string ClientId = "andy-tasks-api";
    private const string TokenEndpoint = "http://andy-auth.test/connect/token";

    [Fact]
    public async Task GetTokenAsync_FetchesAndCachesAccessToken()
    {
        var calls = 0;
        var handler = new StubHandler((req, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse("abc123", expiresIn: 3600));
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var t1 = await provider.GetTokenAsync(CancellationToken.None);
        var t2 = await provider.GetTokenAsync(CancellationToken.None);

        Assert.Equal("abc123", t1);
        Assert.Equal("abc123", t2);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task GetTokenAsync_RefreshesNearExpiry()
    {
        var calls = 0;
        var handler = new StubHandler((req, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse(calls == 1 ? "first" : "second", expiresIn: 120));
        });
        var time = new FakeTimeProvider();
        using var provider = NewProvider(handler, time);

        var t1 = await provider.GetTokenAsync(CancellationToken.None);
        // Expiry is 120s; refresh skew is 60s. Advance to t+59s — still cached.
        time.Advance(TimeSpan.FromSeconds(59));
        var t2 = await provider.GetTokenAsync(CancellationToken.None);
        // Cross the 60s skew boundary — provider must refresh.
        time.Advance(TimeSpan.FromSeconds(2));
        var t3 = await provider.GetTokenAsync(CancellationToken.None);

        Assert.Equal("first", t1);
        Assert.Equal("first", t2);
        Assert.Equal("second", t3);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenAsync_CoalescesConcurrentFirstCalls()
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

        var pending = new[]
        {
            provider.GetTokenAsync(CancellationToken.None),
            provider.GetTokenAsync(CancellationToken.None),
            provider.GetTokenAsync(CancellationToken.None),
        };
        // Give the tasks a chance to enter the gate before we release.
        await Task.Yield();
        release.SetResult();
        var tokens = await Task.WhenAll(pending);

        Assert.All(tokens, t => Assert.Equal("shared", t));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task RefreshTokenAsync_ForcesRoundtrip_EvenWhenCached()
    {
        var calls = 0;
        var handler = new StubHandler((_, _) =>
        {
            calls++;
            return Task.FromResult(TokenResponse(calls == 1 ? "stale" : "fresh", expiresIn: 3600));
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var cached = await provider.GetTokenAsync(CancellationToken.None);
        var refreshed = await provider.RefreshTokenAsync(CancellationToken.None);

        Assert.Equal("stale", cached);
        Assert.Equal("fresh", refreshed);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WhenEndpointReturnsError()
    {
        var handler = new StubHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("{\"error\":\"invalid_client\"}"),
            }));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenAsync(CancellationToken.None));
        Assert.Contains("[M2M-TOKEN-REJECTED]", ex.Message);
        Assert.Contains("400", ex.Message);
        Assert.Contains("invalid_client", ex.Message);
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WhenTokenEndpointUnreachable()
    {
        var handler = new StubHandler((_, _) =>
            Task.FromException<HttpResponseMessage>(new HttpRequestException("connect failed")));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenAsync(CancellationToken.None));
        Assert.Contains("[M2M-TOKEN-UNREACHABLE]", ex.Message);
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WhenAccessTokenEmpty()
    {
        var handler = new StubHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"access_token\":\"\",\"expires_in\":3600}",
                    Encoding.UTF8, "application/json"),
            }));
        using var provider = NewProvider(handler, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenAsync(CancellationToken.None));
        Assert.Contains("[M2M-TOKEN-EMPTY]", ex.Message);
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WithCode_WhenClientIdMissing()
    {
        var handler = new StubHandler((_, _) =>
            Task.FromResult(TokenResponse("unused", 60)));
        var http = new HttpClient(handler);
        var factory = new SingleClientFactory(http);
        var options = Options.Create(new AndyAuthM2MOptions
        {
            TokenEndpoint = TokenEndpoint,
            // ClientId intentionally omitted
            ClientSecretEnvVar = EnvVar,
        });
        using var provider = new ClientCredentialsTokenProvider(
            factory, options, new FakeTimeProvider(),
            NullLogger<ClientCredentialsTokenProvider>.Instance);

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenAsync(CancellationToken.None));
        Assert.Contains("[M2M-TOKEN-NOCLIENTID]", ex.Message);
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WithCode_WhenSecretEnvVarMissing()
    {
        var handler = new StubHandler((_, _) =>
            Task.FromResult(TokenResponse("unused", 60)));
        var http = new HttpClient(handler);
        var factory = new SingleClientFactory(http);
        var options = Options.Create(new AndyAuthM2MOptions
        {
            TokenEndpoint = TokenEndpoint,
            ClientId = ClientId,
            // ClientSecretEnvVar intentionally omitted
        });
        using var provider = new ClientCredentialsTokenProvider(
            factory, options, new FakeTimeProvider(),
            NullLogger<ClientCredentialsTokenProvider>.Instance);

        var ex = await Assert.ThrowsAsync<ServiceTokenException>(() =>
            provider.GetTokenAsync(CancellationToken.None));
        Assert.Contains("[M2M-TOKEN-NOSECRETENV]", ex.Message);
    }

    [Fact]
    public async Task GetTokenAsync_SendsClientCredentialsForm()
    {
        Environment.SetEnvironmentVariable(EnvVar, "real-secret");
        try
        {
            string? observed = null;
            var handler = new StubHandler(async (req, ct) =>
            {
                observed = await req.Content!.ReadAsStringAsync(ct);
                return TokenResponse("ok", 60);
            });
            using var provider = NewProvider(handler, new FakeTimeProvider(), scope: "scp:urn:andy-settings-api");

            await provider.GetTokenAsync(CancellationToken.None);

            Assert.NotNull(observed);
            Assert.Contains("grant_type=client_credentials", observed);
            Assert.Contains("client_id=andy-tasks-api", observed);
            Assert.Contains("client_secret=real-secret", observed);
            Assert.Contains("scope=scp", observed);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnvVar, null);
        }
    }

    [Fact]
    public async Task GetTokenAsync_FallsBackToDevSecret_WhenEnvVarUnset()
    {
        Environment.SetEnvironmentVariable(EnvVar, null);
        string? observed = null;
        var handler = new StubHandler(async (req, ct) =>
        {
            observed = await req.Content!.ReadAsStringAsync(ct);
            return TokenResponse("ok", 60);
        });
        using var provider = NewProvider(handler, new FakeTimeProvider());

        await provider.GetTokenAsync(CancellationToken.None);

        Assert.NotNull(observed);
        Assert.Contains("client_secret=andy-tasks-api-secret-change-in-production", observed);
    }

    private static ClientCredentialsTokenProvider NewProvider(
        HttpMessageHandler handler, TimeProvider time, string? scope = null)
    {
        var http = new HttpClient(handler);
        var factory = new SingleClientFactory(http);
        var options = Options.Create(new AndyAuthM2MOptions
        {
            TokenEndpoint = TokenEndpoint,
            ClientId = ClientId,
            ClientSecretEnvVar = EnvVar,
            Scope = scope,
        });
        return new ClientCredentialsTokenProvider(
            factory, options, time, NullLogger<ClientCredentialsTokenProvider>.Instance);
    }

    private static HttpResponseMessage TokenResponse(string accessToken, int expiresIn)
    {
        var json = $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"Bearer\",\"expires_in\":{expiresIn}}}";
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
