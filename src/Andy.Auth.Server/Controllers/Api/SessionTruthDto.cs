using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Controllers.Api;

/// <summary>
/// Authoritative, machine-readable snapshot of the caller's session state,
/// returned by <c>GET /auth/session</c>.
/// <para>
/// SM.2.1 (rivoli-ai/conductor#2003): this is the §7.2 "session-truth" the
/// client reconciles its durable "I think I'm signed in" marker against on
/// launch. A revoked session is reported with <see cref="Revoked"/> = true and
/// <see cref="Authenticated"/> = false — NEVER a generic 500 — so the client can
/// distinguish a real sign-out from a transient blip.
/// </para>
/// </summary>
public class SessionTruthDto
{
    /// <summary>
    /// True when the bearer token resolves to a live, non-revoked, non-expired
    /// session for an account that still exists and is allowed to sign in.
    /// </summary>
    [JsonPropertyName("authenticated")]
    public bool Authenticated { get; set; }

    /// <summary>
    /// The subject (user id) the token is bound to, when resolvable. Null when
    /// the token maps to no known account (deleted / never existed).
    /// </summary>
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    /// <summary>
    /// The server-side session identifier this truth refers to, when one exists.
    /// </summary>
    [JsonPropertyName("sessionId")]
    public string? SessionId { get; set; }

    /// <summary>
    /// When the session expires (UTC), when known.
    /// </summary>
    [JsonPropertyName("expiresAt")]
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// True when the session was explicitly revoked (admin force-logout, account
    /// delete, /signout revoke-all, concurrent-session-limit, inactivity). A
    /// revoked session is a PERMANENT sign-out signal — the client must not retry.
    /// </summary>
    [JsonPropertyName("revoked")]
    public bool Revoked { get; set; }

    /// <summary>
    /// When the session was revoked (UTC), when applicable. Acts as the
    /// monotonically-increasing watermark a client uses to reconcile a stale
    /// status fetch against a newer revocation observation.
    /// </summary>
    [JsonPropertyName("revokedAt")]
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Stable reason code when revoked, e.g. <c>session_revoked</c>. Mirrors the
    /// 410-Gone body so a client gets the same code from either channel.
    /// </summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}

/// <summary>
/// SM.2.1 error taxonomy. These codes let a client cleanly separate a
/// <b>transient</b> failure (retry) from a <b>permanent</b> one (sign out),
/// closing the #1861 "all-red on launch" conflation where a 5xx blip was
/// treated identically to a real 401/revocation.
/// </summary>
public static class SessionErrorCodes
{
    /// <summary>401 — the bearer token is invalid/expired or bound to an account
    /// that no longer exists. PERMANENT → the client signs out.</summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>410 — the session was explicitly revoked. PERMANENT → sign out.
    /// This is the §7.4 explicit revocation signal SessionState consumes instead
    /// of a timeout/5xx heuristic.</summary>
    public const string SessionRevoked = "session_revoked";

    /// <summary>503 — an upstream/dependency the auth service depends on is
    /// momentarily unavailable. TRANSIENT → the client retries (honoring
    /// Retry-After). MUST NOT be collapsed into a 401.</summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";
}

/// <summary>
/// Minimal typed error body returned alongside the 410 / 503 status codes.
/// </summary>
public class SessionErrorDto
{
    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}
