using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Mints and verifies the signed, narrowly-scoped capability that authorizes a
/// single OAuth broker callback mutation
/// (<c>POST /auth/oauth/authorizations/{id}/callback</c> and
/// <c>.../exchange-result</c>).
/// <para>
/// Issue #123: the provider callback arrives on a browser redirect with no
/// bearer token in flight, so the callback-classification endpoints were
/// <c>[AllowAnonymous]</c> and knowledge of the authorization UUID acted as the
/// only capability. This service closes that gap: at /authorize time the broker
/// vends a capability token bound to the authorization id <b>and</b> provider,
/// signed with ASP.NET Data Protection. The callback endpoints accept the
/// mutation only when the caller presents a valid capability (or authenticates
/// as a broker/service identity) — the UUID alone is no longer sufficient.
/// </para>
/// <para>
/// The token is time-limited to the authorization's own TTL via
/// <see cref="ITimeLimitedDataProtector"/>, so a leaked capability cannot be
/// replayed past the flow's lifetime. It is effectively single-use because it
/// authorizes exactly one terminal transition: once the authorization reaches a
/// terminal state, a replay is rejected with 409 by the service state machine.
/// </para>
/// </summary>
public class OAuthCallbackCapabilityService
{
    // Data Protection purpose string — isolates this protector's keys from every
    // other consumer of the app's data-protection ring (antiforgery, Identity …).
    private const string ProtectorPurpose = "Andy.Auth.Server.OAuthCallbackCapability.v1";

    // Payload discriminator so a future format change can be detected/rejected.
    private const string PayloadVersion = "v1";

    private readonly ITimeLimitedDataProtector _protector;

    public OAuthCallbackCapabilityService(IDataProtectionProvider dataProtectionProvider)
    {
        _protector = dataProtectionProvider
            .CreateProtector(ProtectorPurpose)
            .ToTimeLimitedDataProtector();
    }

    /// <summary>
    /// Mints a capability token bound to <paramref name="authorizationId"/> and
    /// <paramref name="provider"/>, valid until <paramref name="expiresAt"/>.
    /// </summary>
    public string Issue(Guid authorizationId, string provider, DateTime expiresAt)
    {
        if (string.IsNullOrWhiteSpace(provider))
            throw new ArgumentException("provider is required", nameof(provider));

        var payload = $"{PayloadVersion}|{authorizationId:N}|{provider}";
        // Never mint an already-expired token; clamp to a minimal positive window.
        var expiration = expiresAt > DateTime.UtcNow
            ? new DateTimeOffset(expiresAt, TimeSpan.Zero)
            : DateTimeOffset.UtcNow.AddSeconds(1);

        return _protector.Protect(payload, expiration);
    }

    /// <summary>
    /// Verifies that <paramref name="token"/> is a valid, unexpired capability
    /// bound to <paramref name="authorizationId"/> and <paramref name="provider"/>.
    /// Returns <c>true</c> only when the signature verifies, the token has not
    /// expired, and both the id and provider bindings match — a tampered token,
    /// an expired token, or a token minted for a different authorization/provider
    /// all return <c>false</c>.
    /// </summary>
    public bool Validate(string? token, Guid authorizationId, string provider)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(provider))
            return false;

        string payload;
        try
        {
            payload = _protector.Unprotect(token);
        }
        catch (CryptographicException)
        {
            // Tampered signature or expired (ITimeLimitedDataProtector raises
            // CryptographicException past the expiry) — reject.
            return false;
        }

        var parts = payload.Split('|');
        if (parts.Length != 3 || parts[0] != PayloadVersion)
            return false;

        if (!Guid.TryParseExact(parts[1], "N", out var boundId) || boundId != authorizationId)
            return false;

        return string.Equals(parts[2], provider, StringComparison.Ordinal);
    }
}
