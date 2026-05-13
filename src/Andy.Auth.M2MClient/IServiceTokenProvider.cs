// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Andy.Auth.M2MClient;

/// <summary>
/// Provides cached <c>client_credentials</c> access tokens for
/// service-to-service HTTP calls. Implementations are expected to
/// refresh ahead of expiry and coalesce concurrent callers behind a
/// single in-flight refresh task.
/// </summary>
public interface IServiceTokenProvider
{
    /// <summary>
    /// Returns a valid bearer token, refreshing from the OAuth2 token
    /// endpoint when the cached one is missing or near expiry. Throws
    /// <see cref="ServiceTokenException"/> if the endpoint is
    /// unreachable, rejects the credentials, or returns an empty
    /// <c>access_token</c>.
    /// </summary>
    Task<string> GetTokenAsync(CancellationToken ct = default);
}
