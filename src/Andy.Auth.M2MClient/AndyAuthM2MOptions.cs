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
