// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Andy.Auth.M2MClient;

/// <summary>
/// RFC 8693 OAuth 2.0 Token Exchange implementation of
/// <see cref="IDelegatedTokenProvider"/>.
///
/// Posts <c>grant_type=urn:ietf:params:oauth:grant-type:token-exchange</c>
/// to the andy-auth token endpoint, presenting the caller's own
/// <c>client_credentials</c> (from <see cref="AndyAuthM2MOptions"/>)
/// together with the supplied <c>subject_token</c> and target
/// <c>resource</c> (audience). The returned access token has
/// <c>sub</c>=user, <c>act</c>=service, <c>aud</c>=audience.
///
/// Caching is per (<c>subject_token</c>, <c>audience</c>) — keyed by a
/// SHA-256 hash of the subject token so the raw user JWT never lives
/// in a cache key. Concurrent callers for the same key coalesce behind
/// a single in-flight task, same pattern as
/// <see cref="ClientCredentialsTokenProvider"/>.
///
/// Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
public sealed class TokenExchangeDelegatedTokenProvider : IDelegatedTokenProvider, IDisposable
{
    /// <summary>
    /// RFC 8693 §2.1 grant-type URN.
    /// </summary>
    public const string GrantTypeUrn = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>
    /// RFC 8693 §3 token-type URN identifying an OAuth 2.0 access
    /// token. The only <c>subject_token_type</c> we send.
    /// </summary>
    public const string AccessTokenTypeUrn = "urn:ietf:params:oauth:token-type:access_token";

    private static readonly TimeSpan RefreshSkew = TimeSpan.FromSeconds(60);

    private readonly IHttpClientFactory _factory;
    private readonly AndyAuthM2MOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<TokenExchangeDelegatedTokenProvider> _logger;

    /// <summary>
    /// Per-(subjectTokenHash, audience) entries. Each holds a
    /// semaphore for in-flight coalescing plus the most-recent cached
    /// token + expiry. The <see cref="ConcurrentDictionary{TKey, TValue}"/>
    /// keeps the fast path lock-free.
    /// </summary>
    private readonly ConcurrentDictionary<CacheKey, CacheEntry> _entries = new();

    public TokenExchangeDelegatedTokenProvider(
        IHttpClientFactory factory,
        IOptions<AndyAuthM2MOptions> options,
        TimeProvider time,
        ILogger<TokenExchangeDelegatedTokenProvider> logger)
    {
        _factory = factory;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    public async Task<string> GetTokenOnBehalfOfAsync(
        string subjectToken,
        string audience,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectToken))
        {
            throw new ServiceTokenException(
                "[M2M-OBO-NOSUBJECT] subject_token must not be empty.");
        }
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ServiceTokenException(
                "[M2M-OBO-NOAUDIENCE] audience must not be empty.");
        }

        var key = new CacheKey(HashSubject(subjectToken), audience);
        var entry = _entries.GetOrAdd(key, _ => new CacheEntry());

        var now = _time.GetUtcNow();
        if (entry.CachedToken is not null && now < entry.CachedUntil - RefreshSkew)
        {
            return entry.CachedToken;
        }

        return await RefreshCoalescedAsync(entry, subjectToken, audience, ct).ConfigureAwait(false);
    }

    private async Task<string> RefreshCoalescedAsync(
        CacheEntry entry,
        string subjectToken,
        string audience,
        CancellationToken ct)
    {
        await entry.Gate.WaitAsync(ct).ConfigureAwait(false);
        Task<string> task;
        try
        {
            var now = _time.GetUtcNow();
            if (entry.CachedToken is not null && now < entry.CachedUntil - RefreshSkew)
            {
                return entry.CachedToken;
            }
            task = entry.Inflight ??= FetchAsync(entry, subjectToken, audience, ct);
        }
        finally
        {
            entry.Gate.Release();
        }

        try
        {
            return await task.ConfigureAwait(false);
        }
        finally
        {
            await entry.Gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                if (ReferenceEquals(entry.Inflight, task))
                {
                    entry.Inflight = null;
                }
            }
            finally
            {
                entry.Gate.Release();
            }
        }
    }

    private async Task<string> FetchAsync(
        CacheEntry entry,
        string subjectToken,
        string audience,
        CancellationToken ct)
    {
        var endpoint = _options.ResolveTokenEndpoint();
        var clientId = _options.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ServiceTokenException(
                "[M2M-OBO-NOCLIENTID] AndyAuth.ClientId is not configured.");
        }
        var secret = ResolveSecret(clientId);

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", GrantTypeUrn),
            new("client_id", clientId),
            new("client_secret", secret),
            new("subject_token", subjectToken),
            new("subject_token_type", AccessTokenTypeUrn),
            new("resource", audience),
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };

        var client = _factory.CreateClient(ClientCredentialsTokenProvider.HttpClientName);
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new ServiceTokenException(
                $"[M2M-OBO-UNREACHABLE] andy-auth token endpoint at {endpoint} is unreachable: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                throw new ServiceTokenException(
                    $"[M2M-OBO-REJECTED] andy-auth token endpoint returned {(int)response.StatusCode} {response.ReasonPhrase} for token exchange (audience={audience}): {body}");
            }

            var payload = await response.Content
                .ReadFromJsonAsync<TokenResponse>(cancellationToken: ct)
                .ConfigureAwait(false);
            if (payload is null || string.IsNullOrEmpty(payload.AccessToken))
            {
                throw new ServiceTokenException(
                    "[M2M-OBO-EMPTY] andy-auth returned an empty access_token for token exchange.");
            }

            var lifetime = payload.ExpiresIn > 0 ? payload.ExpiresIn : 300;
            var expiresAt = _time.GetUtcNow().AddSeconds(lifetime);

            await entry.Gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                entry.CachedToken = payload.AccessToken;
                entry.CachedUntil = expiresAt;
            }
            finally
            {
                entry.Gate.Release();
            }

            _logger.LogDebug(
                "Acquired delegated token for client {ClientId} -> {Audience}; expires in {Lifetime}s",
                clientId, audience, lifetime);
            return payload.AccessToken;
        }
    }

    private string ResolveSecret(string clientId)
    {
        var envVar = _options.ClientSecretEnvVar;
        if (string.IsNullOrWhiteSpace(envVar))
        {
            throw new ServiceTokenException(
                "[M2M-OBO-NOSECRETENV] AndyAuth.ClientSecretEnvVar is not configured; cannot resolve client_secret.");
        }
        var secret = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrEmpty(secret))
        {
            return secret;
        }
        var fallback = $"{clientId}-secret-change-in-production";
        _logger.LogWarning(
            "Environment variable {EnvVar} is not set; falling back to dev secret for client {ClientId}. " +
            "This is fine for dev/embedded but MUST be overridden in production.",
            envVar, clientId);
        return fallback;
    }

    private static string HashSubject(string subjectToken)
    {
        var bytes = Encoding.UTF8.GetBytes(subjectToken);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }

    public void Dispose()
    {
        foreach (var entry in _entries.Values)
        {
            entry.Gate.Dispose();
        }
    }

    private readonly record struct CacheKey(string SubjectTokenHash, string Audience);

    private sealed class CacheEntry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public string? CachedToken;
        public DateTimeOffset CachedUntil;
        public Task<string>? Inflight;
    }

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("issued_token_type")] string? IssuedTokenType);
}
