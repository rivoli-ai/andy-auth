// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Net;
using System.Net.Http.Headers;

namespace Andy.Auth.M2MClient;

/// <summary>
/// Delegating handler that attaches an <c>Authorization: Bearer …</c>
/// header to outbound requests, fetching the token from
/// <see cref="IServiceTokenProvider"/>. On a single <c>401</c> response
/// the handler forces a token refresh and retries once — this catches
/// the edge case where the cached token's lifetime overlaps the
/// authority's actual revocation window. Wire onto named HttpClients
/// via <c>AddHttpMessageHandler&lt;ServiceBearerHandler&gt;()</c>.
/// </summary>
public sealed class ServiceBearerHandler : DelegatingHandler
{
    private readonly IServiceTokenProvider _tokens;

    public ServiceBearerHandler(IServiceTokenProvider tokens)
    {
        _tokens = tokens;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // One-shot retry on 401 — the cached token may have been
        // revoked or rotated mid-flight. The provider's coalescing gate
        // is what stops every concurrent in-flight request from
        // hammering the token endpoint at once.
        if (response.StatusCode != HttpStatusCode.Unauthorized || _tokens is not IRefreshableServiceTokenProvider refreshable)
        {
            return response;
        }
        response.Dispose();
        var refreshed = await refreshable.RefreshTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", refreshed);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Optional capability surface for token providers that can force a
/// refresh independent of the expiry check. <see cref="ClientCredentialsTokenProvider"/>
/// implements this so <see cref="ServiceBearerHandler"/>'s 401-retry can
/// bypass the cache. Custom providers that cannot refresh on demand
/// simply do not implement this interface — the handler then returns
/// the 401 unmodified.
/// </summary>
public interface IRefreshableServiceTokenProvider : IServiceTokenProvider
{
    /// <summary>Forces a token-endpoint round-trip, replacing any cached token.</summary>
    Task<string> RefreshTokenAsync(CancellationToken ct = default);
}
