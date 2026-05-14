// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Andy.Auth.M2MClient;

/// <summary>
/// Acquires <c>client_credentials</c> access tokens from the OAuth2
/// token endpoint and caches them in memory until shortly before
/// expiry. Concurrent callers are coalesced behind a single in-flight
/// refresh task (pattern from Conductor #624's
/// <c>SessionActor.activeRefreshTask</c>).
/// </summary>
public sealed class ClientCredentialsTokenProvider : IRefreshableServiceTokenProvider, IDisposable
{
    /// <summary>Named <see cref="IHttpClientFactory"/> client used for token requests.</summary>
    public const string HttpClientName = "AndyAuthM2M";

    private static readonly TimeSpan RefreshSkew = TimeSpan.FromSeconds(60);

    private readonly IHttpClientFactory _factory;
    private readonly AndyAuthM2MOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<ClientCredentialsTokenProvider> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private string? _cachedToken;
    private DateTimeOffset _cachedUntil;
    private Task<string>? _inflight;

    public ClientCredentialsTokenProvider(
        IHttpClientFactory factory,
        IOptions<AndyAuthM2MOptions> options,
        TimeProvider time,
        ILogger<ClientCredentialsTokenProvider> logger)
    {
        _factory = factory;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    public Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        if (_cachedToken is not null && now < _cachedUntil - RefreshSkew)
        {
            return Task.FromResult(_cachedToken);
        }
        return RefreshCoalescedAsync(ct);
    }

    /// <summary>
    /// Forces a token-endpoint round-trip, ignoring the cached token's
    /// expiry. Used by <see cref="ServiceBearerHandler"/> when a
    /// downstream call still returns 401 with the cached token.
    /// Concurrent forced-refresh calls coalesce behind the same gate
    /// as the regular path.
    /// </summary>
    public Task<string> RefreshTokenAsync(CancellationToken ct = default)
    {
        _cachedToken = null;
        _cachedUntil = DateTimeOffset.MinValue;
        return RefreshCoalescedAsync(ct);
    }

    private async Task<string> RefreshCoalescedAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        Task<string> task;
        try
        {
            var now = _time.GetUtcNow();
            if (_cachedToken is not null && now < _cachedUntil - RefreshSkew)
            {
                return _cachedToken;
            }
            task = _inflight ??= FetchAsync(ct);
        }
        finally
        {
            _gate.Release();
        }

        try
        {
            return await task.ConfigureAwait(false);
        }
        finally
        {
            await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                if (ReferenceEquals(_inflight, task))
                {
                    _inflight = null;
                }
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    /// <summary>
    /// Retry schedule used when the token endpoint returns a transient
    /// failure (502/503/504 / connection refused / DNS / TLS errors).
    /// Total wall-clock ~7.7s before giving up — long enough to cover
    /// andy-auth's typical cold-start, short enough to fail fast on
    /// genuinely-misconfigured deployments.
    ///
    /// Cold-start race documented at conductor#XXXX (PV epic): every
    /// service spawned in the application wave hits andy-auth for an
    /// M2M token within milliseconds of its own start; if andy-auth
    /// hasn't bound its listener yet the proxy returns 502 and the
    /// caller's hosted bootstrapper (e.g.
    /// <c>PlannerSettingsBootstrapper</c>) calls
    /// <c>StopApplication</c>. The retry collapses that race onto a
    /// successful second-or-third attempt without flapping.
    /// </summary>
    private static readonly TimeSpan[] RetryBackoffs =
    {
        TimeSpan.FromMilliseconds(200),
        TimeSpan.FromMilliseconds(500),
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
    };

    private async Task<string> FetchAsync(CancellationToken ct)
    {
        Exception? lastTransient = null;
        for (var attempt = 0; attempt <= RetryBackoffs.Length; attempt++)
        {
            try
            {
                return await FetchOnceAsync(ct).ConfigureAwait(false);
            }
            catch (ServiceTokenException ex) when (IsTransient(ex) && attempt < RetryBackoffs.Length)
            {
                lastTransient = ex;
                _logger.LogDebug(
                    "M2M token fetch attempt {Attempt}/{Total} failed transiently ({Code}); retrying in {Delay}ms",
                    attempt + 1,
                    RetryBackoffs.Length + 1,
                    ExtractCode(ex),
                    RetryBackoffs[attempt].TotalMilliseconds);
                await Task.Delay(RetryBackoffs[attempt], ct).ConfigureAwait(false);
            }
        }
        // All retries exhausted on transient failures — surface the
        // last error verbatim so the caller logs the same diagnostic
        // it would have without retry.
        throw lastTransient
            ?? new ServiceTokenException("[M2M-TOKEN-RETRY-EXHAUSTED] Token fetch failed after retries.");
    }

    /// <summary>
    /// Classifies a <see cref="ServiceTokenException"/> as a transient
    /// connectivity / cold-start condition that should be retried.
    /// Pulls the status code out of the message string because the
    /// exception type doesn't carry it structurally today; matches the
    /// codes the message wrapper produces.
    /// </summary>
    private static bool IsTransient(ServiceTokenException ex)
    {
        var msg = ex.Message;
        // Connection refused / DNS / TLS — every call into FetchOnceAsync
        // that throws HttpRequestException wraps under this prefix.
        if (msg.Contains("[M2M-TOKEN-UNREACHABLE]", StringComparison.Ordinal)) return true;
        // HTTP-status path. Match the gateway-layer codes the proxy
        // surfaces during cold-start. 502/503/504 are universally
        // retryable; 408 (Request Timeout) and 429 (Too Many Requests)
        // are added defensively.
        if (msg.Contains("returned 502", StringComparison.Ordinal)) return true;
        if (msg.Contains("returned 503", StringComparison.Ordinal)) return true;
        if (msg.Contains("returned 504", StringComparison.Ordinal)) return true;
        if (msg.Contains("returned 408", StringComparison.Ordinal)) return true;
        if (msg.Contains("returned 429", StringComparison.Ordinal)) return true;
        return false;
    }

    private static string ExtractCode(ServiceTokenException ex)
    {
        var msg = ex.Message;
        var start = msg.IndexOf('[');
        var end = msg.IndexOf(']');
        if (start >= 0 && end > start) return msg.Substring(start + 1, end - start - 1);
        return "unknown";
    }

    /// <summary>
    /// Single token-fetch attempt. The retry wrapper in
    /// <see cref="FetchAsync"/> calls this in a loop on transient
    /// failures; non-transient failures (invalid credentials,
    /// malformed responses) propagate immediately.
    /// </summary>
    private async Task<string> FetchOnceAsync(CancellationToken ct)
    {
        var endpoint = _options.ResolveTokenEndpoint();
        var clientId = _options.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ServiceTokenException(
                "[M2M-TOKEN-NOCLIENTID] AndyAuth.ClientId is not configured.");
        }
        var secret = ResolveSecret(clientId);

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
            new("client_id", clientId),
            new("client_secret", secret),
        };
        if (!string.IsNullOrWhiteSpace(_options.Scope))
        {
            form.Add(new KeyValuePair<string, string>("scope", _options.Scope!));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };

        var client = _factory.CreateClient(HttpClientName);
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new ServiceTokenException(
                $"[M2M-TOKEN-UNREACHABLE] andy-auth token endpoint at {endpoint} is unreachable: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                throw new ServiceTokenException(
                    $"[M2M-TOKEN-REJECTED] andy-auth token endpoint returned {(int)response.StatusCode} {response.ReasonPhrase}: {body}");
            }

            var payload = await response.Content
                .ReadFromJsonAsync<TokenResponse>(cancellationToken: ct)
                .ConfigureAwait(false);
            if (payload is null || string.IsNullOrEmpty(payload.AccessToken))
            {
                throw new ServiceTokenException(
                    "[M2M-TOKEN-EMPTY] andy-auth returned an empty access_token.");
            }

            var lifetime = payload.ExpiresIn > 0 ? payload.ExpiresIn : 300;
            var expiresAt = _time.GetUtcNow().AddSeconds(lifetime);

            await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                _cachedToken = payload.AccessToken;
                _cachedUntil = expiresAt;
            }
            finally
            {
                _gate.Release();
            }

            _logger.LogDebug(
                "Acquired M2M token for client {ClientId}; expires in {Lifetime}s",
                clientId, lifetime);
            return payload.AccessToken;
        }
    }

    private string ResolveSecret(string clientId)
    {
        var envVar = _options.ClientSecretEnvVar;
        if (string.IsNullOrWhiteSpace(envVar))
        {
            throw new ServiceTokenException(
                "[M2M-TOKEN-NOSECRETENV] AndyAuth.ClientSecretEnvVar is not configured; cannot resolve client_secret.");
        }
        var secret = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrEmpty(secret))
        {
            return secret;
        }
        // Mirror andy-auth DbSeeder.ResolveClientSecret: when the env var is
        // unset, fall back to "{clientId}-secret-change-in-production". Loud
        // warning so production misconfig is obvious.
        var fallback = $"{clientId}-secret-change-in-production";
        _logger.LogWarning(
            "Environment variable {EnvVar} is not set; falling back to dev secret for client {ClientId}. " +
            "This is fine for dev/embedded but MUST be overridden in production.",
            envVar, clientId);
        return fallback;
    }

    public void Dispose() => _gate.Dispose();

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);
}
