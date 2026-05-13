// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Net;
using Andy.Auth.M2MClient;
using Xunit;

namespace Andy.Auth.M2MClient.Tests;

public sealed class ServiceBearerHandlerTests
{
    [Fact]
    public async Task SendAsync_AttachesBearerToken()
    {
        string? observed = null;
        var inner = new StubHandler((req, _) =>
        {
            observed = req.Headers.Authorization?.ToString();
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        var handler = new ServiceBearerHandler(new FakeTokenProvider("token-abc"))
        {
            InnerHandler = inner,
        };
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://example.test/ping");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("Bearer token-abc", observed);
    }

    [Fact]
    public async Task SendAsync_OverwritesExistingAuthorization()
    {
        string? observed = null;
        var inner = new StubHandler((req, _) =>
        {
            observed = req.Headers.Authorization?.ToString();
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var handler = new ServiceBearerHandler(new FakeTokenProvider("fresh"))
        {
            InnerHandler = inner,
        };
        using var client = new HttpClient(handler);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.test/ping");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "stale");

        await client.SendAsync(request);

        Assert.Equal("Bearer fresh", observed);
    }

    [Fact]
    public async Task SendAsync_Retries_OnceOn401_WithRefreshedToken()
    {
        var tokens = new[] { "first", "second" };
        var index = 0;
        var sentTokens = new List<string?>();
        var inner = new StubHandler((req, _) =>
        {
            sentTokens.Add(req.Headers.Authorization?.Parameter);
            // First call -> 401; second call -> 200.
            return sentTokens.Count == 1
                ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
                : new HttpResponseMessage(HttpStatusCode.OK);
        });
        var provider = new FakeRefreshableTokenProvider(() => tokens[Math.Min(index++, tokens.Length - 1)]);
        var handler = new ServiceBearerHandler(provider) { InnerHandler = inner };
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://example.test/secured");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(new[] { "first", "second" }, sentTokens);
        Assert.Equal(1, provider.RefreshCalls);
    }

    [Fact]
    public async Task SendAsync_DoesNotRetry_OnSecond401()
    {
        var sentTokens = new List<string?>();
        var inner = new StubHandler((req, _) =>
        {
            sentTokens.Add(req.Headers.Authorization?.Parameter);
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        });
        var provider = new FakeRefreshableTokenProvider(() => "always-bad");
        var handler = new ServiceBearerHandler(provider) { InnerHandler = inner };
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://example.test/secured");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // Exactly two attempts — initial + one retry, never a third.
        Assert.Equal(2, sentTokens.Count);
    }

    [Fact]
    public async Task SendAsync_DoesNotRetry_WhenProviderIsNotRefreshable()
    {
        var sentTokens = new List<string?>();
        var inner = new StubHandler((req, _) =>
        {
            sentTokens.Add(req.Headers.Authorization?.Parameter);
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        });
        // FakeTokenProvider does not implement IRefreshableServiceTokenProvider.
        var handler = new ServiceBearerHandler(new FakeTokenProvider("just-one"))
        {
            InnerHandler = inner,
        };
        using var client = new HttpClient(handler);

        await client.GetAsync("https://example.test/secured");

        Assert.Single(sentTokens);
        Assert.Equal("just-one", sentTokens[0]);
    }

    private sealed class FakeTokenProvider : IServiceTokenProvider
    {
        private readonly string _token;
        public FakeTokenProvider(string token) { _token = token; }
        public Task<string> GetTokenAsync(CancellationToken ct = default) => Task.FromResult(_token);
    }

    private sealed class FakeRefreshableTokenProvider : IRefreshableServiceTokenProvider
    {
        private readonly Func<string> _next;
        private string? _current;
        public int RefreshCalls { get; private set; }

        public FakeRefreshableTokenProvider(Func<string> next) { _next = next; }

        public Task<string> GetTokenAsync(CancellationToken ct = default)
            => Task.FromResult(_current ??= _next());

        public Task<string> RefreshTokenAsync(CancellationToken ct = default)
        {
            RefreshCalls++;
            _current = _next();
            return Task.FromResult(_current);
        }
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _respond;
        public StubHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> respond)
        {
            _respond = respond;
        }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_respond(request, cancellationToken));
    }
}
