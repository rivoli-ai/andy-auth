// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Andy.Auth.M2MClient;

/// <summary>
/// Provides cached <em>on-behalf-of</em> access tokens via the RFC 8693
/// OAuth 2.0 Token Exchange grant. Where
/// <see cref="IServiceTokenProvider"/> mints a token for the service
/// itself, this interface mints a token where:
///
/// <list type="bullet">
///   <item><description><c>sub</c> is the original end user (taken from the supplied <c>subjectToken</c>),</description></item>
///   <item><description><c>act</c> records the calling service as the actor,</description></item>
///   <item><description><c>aud</c> names the requested downstream service.</description></item>
/// </list>
///
/// Use this on any service-to-service call that originates from a user
/// request — without it, the downstream RBAC check sees only the
/// service principal (and falls back to <c>anonymous</c> when the
/// service identity isn't an RBAC subject) instead of the actual user.
/// That failure mode is what rivoli-ai/andy-containers#305 exposed.
///
/// Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
public interface IDelegatedTokenProvider
{
    /// <summary>
    /// Returns a valid bearer token issued via token exchange.
    ///
    /// The supplied <paramref name="subjectToken"/> must be an access
    /// token issued by the same andy-auth this provider talks to (the
    /// server-side validator rejects tokens from other issuers).
    /// <paramref name="audience"/> names the downstream service the
    /// returned token will be presented to (e.g.
    /// <c>urn:andy-models-api</c>); the same value is used as the OAuth
    /// 2.0 <c>resource</c> parameter on the token request.
    ///
    /// Implementations cache by (<paramref name="subjectToken"/>,
    /// <paramref name="audience"/>) and refresh ahead of expiry.
    /// Concurrent callers for the same key coalesce behind a single
    /// in-flight request.
    /// </summary>
    /// <exception cref="ServiceTokenException">
    /// Thrown when the token endpoint is unreachable, rejects the
    /// request (e.g. policy denial → <c>unauthorized_client</c>,
    /// invalid subject token → <c>invalid_grant</c>), or returns an
    /// empty <c>access_token</c>. The message carries an
    /// <c>[M2M-*]</c> prefix the caller can grep / surface.
    /// </exception>
    Task<string> GetTokenOnBehalfOfAsync(
        string subjectToken,
        string audience,
        CancellationToken ct = default);
}
