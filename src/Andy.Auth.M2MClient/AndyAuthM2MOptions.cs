// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Andy.Auth.M2MClient;

/// <summary>
/// Strongly-typed binding for the outbound machine-to-machine slice of
/// the <c>AndyAuth</c> configuration section. The inbound JWT-bearer
/// settings (Authority, Audience) belong on the consumer's own
/// authentication middleware and are intentionally out of scope here.
/// </summary>
public sealed class AndyAuthM2MOptions
{
    /// <summary>Configuration section name (<c>AndyAuth</c>).</summary>
    public const string SectionName = "AndyAuth";

    /// <summary>
    /// OIDC authority URL. Used to derive the token endpoint when
    /// <see cref="TokenEndpoint"/> is not set explicitly.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Full token endpoint URL. When empty, falls back to
    /// <c>{Authority}/connect/token</c>. Set this explicitly when the
    /// authority and token endpoint live behind different proxy paths
    /// (e.g. embedded mode behind Conductor's UnifiedProxy).
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>OAuth2 <c>client_id</c> for outbound M2M calls (e.g. <c>andy-tasks-api</c>).</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Name of the environment variable holding this service's
    /// <c>client_secret</c>. Decoupled from the value so the same code
    /// works across deployment modes (dotnet/docker/embedded) without
    /// hard-coding a secret-source convention.
    /// </summary>
    public string ClientSecretEnvVar { get; set; } = string.Empty;

    /// <summary>
    /// Optional <c>scope</c> parameter on the token request. Leave empty
    /// to let the authority pick a default. Operators set this when a
    /// target service requires a specific audience/scope.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Maximum total wall-clock the token provider keeps retrying
    /// <em>transient</em> token-endpoint failures (connection-refused /
    /// DNS / TLS, and gateway 502/503/504/408/429) before giving up and
    /// surfacing the last error.
    ///
    /// Covers the embedded full-fleet cold start (conductor#1902): every
    /// service spawned in the application wave dials andy-auth for an M2M
    /// token within milliseconds of its own start, but the route to
    /// andy-auth through Conductor's UnifiedProxy (e.g.
    /// <c>http://localhost:9100/auth/connect/token</c>) may not be live
    /// for tens of seconds after this service starts (postgres + zot +
    /// nats + andy-auth migration all have to complete first). With the
    /// budget set generously the fetch succeeds on a later attempt
    /// instead of exhausting — so the caller never sees an exception to
    /// log, and the planner gets its real settings rather than degrading.
    ///
    /// Bounded so a genuinely-misconfigured deployment (wrong endpoint,
    /// auth permanently down) still fails fast-ish rather than hanging
    /// forever. The success path returns as soon as auth is reachable
    /// (typically a few seconds), so this is only the worst-case wait.
    /// Set to <see cref="TimeSpan.Zero"/> to disable retries entirely
    /// (first failure propagates immediately).
    /// </summary>
    public TimeSpan StartupRetryBudget { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>True when M2M outbound auth is configured.</summary>
    public bool IsEnabled =>
        !string.IsNullOrWhiteSpace(ClientId) &&
        !string.IsNullOrWhiteSpace(ClientSecretEnvVar) &&
        (!string.IsNullOrWhiteSpace(TokenEndpoint) || !string.IsNullOrWhiteSpace(Authority));

    /// <summary>
    /// Resolves the token endpoint URL: explicit <see cref="TokenEndpoint"/>
    /// wins; otherwise <c>{Authority}/connect/token</c>.
    /// </summary>
    public Uri ResolveTokenEndpoint()
    {
        if (!string.IsNullOrWhiteSpace(TokenEndpoint))
        {
            return new Uri(TokenEndpoint);
        }
        if (string.IsNullOrWhiteSpace(Authority))
        {
            throw new InvalidOperationException(
                "[M2M-OPTS-NOENDPOINT] AndyAuth.TokenEndpoint is empty and " +
                "AndyAuth.Authority is not set; cannot resolve the OAuth2 token endpoint.");
        }
        return new Uri(Authority.TrimEnd('/') + "/connect/token");
    }
}
