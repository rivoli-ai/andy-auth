using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Persisted record of an in-flight or terminal OAuth broker authorization,
/// created at /auth/oauth/authorize time and updated on callback completion.
/// <para>
/// SM.2.2 (rivoli-ai/conductor#2004): this is the server-side fact of record
/// for each third-party provider connection attempt initiated through the andy-auth
/// OAuth broker. Conductor's <c>OAuthFlowState</c> (SM.8) reflects this record
/// on relaunch so a crash mid-exchange never leaves the client stranded in an
/// ambiguous <c>.exchangingCode</c> state.
/// </para>
/// </summary>
public class OAuthAuthorization
{
    /// <summary>
    /// Surrogate primary key.
    /// </summary>
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Public identifier vended to the caller at /authorize time and embedded in
    /// callback deep-links. Clients use this to call GET /auth/oauth/authorizations/{id}.
    /// </summary>
    [Required]
    public Guid AuthorizationId { get; set; } = Guid.NewGuid();

    /// <summary>
    /// The andy-auth subject (user ID) who initiated this authorization.
    /// Null for guest / pre-login broker flows.
    /// </summary>
    [MaxLength(450)]
    public string? SubjectId { get; set; }

    /// <summary>
    /// The external OAuth provider (e.g. "github", "gitlab", "azure_devops").
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string Provider { get; set; } = null!;

    /// <summary>
    /// The OAuth anti-forgery state token sent to the provider.
    /// Stored here so the callback can validate it against the returned <c>state</c>
    /// param without relying solely on session cookies (which crash-killed clients
    /// may have lost). SHA-256 hash stored, not the raw value.
    /// </summary>
    [MaxLength(128)]
    public string? StateTokenHash { get; set; }

    /// <summary>
    /// Current lifecycle state of the authorization.
    /// </summary>
    public OAuthAuthorizationState State { get; set; } = OAuthAuthorizationState.Pending;

    /// <summary>
    /// Structured failure discriminator. Set when State transitions to Failed.
    /// Null when State is Pending or Completed.
    /// </summary>
    public OAuthFailureReason? FailureReason { get; set; }

    /// <summary>
    /// Human-readable detail for the failure. Never contains secrets.
    /// </summary>
    [MaxLength(500)]
    public string? FailureDetail { get; set; }

    /// <summary>
    /// When the authorization was initiated (UTC).
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the authorization expires if not completed (UTC). Defaults to
    /// 10 minutes after creation — matching typical provider authorization TTLs.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// When the authorization reached its terminal state (Completed/Failed/Expired).
    /// Null while Pending.
    /// </summary>
    public DateTime? CompletedAt { get; set; }

    /// <summary>
    /// The connection record created on successful exchange, when applicable.
    /// Stored as a string because andy-auth does not own the connection schema;
    /// the broker persists the connection reference from the consuming service.
    /// </summary>
    [MaxLength(450)]
    public string? ConnectionId { get; set; }

    // ── derived helpers ────────────────────────────────────────────────────────

    /// <summary>True when the record has reached a terminal state.</summary>
    [NotMapped]
    public bool IsTerminal =>
        State is OAuthAuthorizationState.Completed
            or OAuthAuthorizationState.Failed
            or OAuthAuthorizationState.Expired;

    /// <summary>
    /// True when the authorization has been pending past its expiry and has not
    /// yet been explicitly marked Expired.
    /// </summary>
    [NotMapped]
    public bool IsStaleAndPending =>
        State == OAuthAuthorizationState.Pending && DateTime.UtcNow >= ExpiresAt;
}

/// <summary>
/// Lifecycle states for an <see cref="OAuthAuthorization"/>.
/// The valid transitions are:
/// <code>
/// Pending → Completed
/// Pending → Failed
/// Pending → Expired   (via clean-up job or status query)
/// </code>
/// All other transitions are illegal and MUST be rejected by
/// <see cref="Services.OAuthAuthorizationService"/>.
/// </summary>
public enum OAuthAuthorizationState
{
    /// <summary>Initiated; awaiting callback from the provider.</summary>
    Pending = 0,

    /// <summary>Token exchange succeeded; a connection record exists.</summary>
    Completed = 1,

    /// <summary>Terminal failure. See <see cref="OAuthAuthorization.FailureReason"/> for cause.</summary>
    Failed = 2,

    /// <summary>Pending authorization was not completed before <see cref="OAuthAuthorization.ExpiresAt"/>.</summary>
    Expired = 3
}

/// <summary>
/// Structured failure discriminator for a terminal OAuth authorization.
/// These values map 1-to-1 onto the <c>OAuthError</c> enum in Conductor's
/// <c>OAuthState.swift</c>, closing the SM.2.2 round-trip contract.
/// <code>
/// user_denied         → OAuthError.permissionDenied
/// state_mismatch      → OAuthError.stateMismatch
/// token_exchange_failed → OAuthError.exchangeFailed
/// invalid_callback    → OAuthError.invalidCallback
/// </code>
/// </summary>
public enum OAuthFailureReason
{
    /// <summary>
    /// The provider returned <c>error=access_denied</c> — the user explicitly
    /// refused to grant permissions. Maps to <c>OAuthError.permissionDenied</c>.
    /// </summary>
    UserDenied = 0,

    /// <summary>
    /// The anti-forgery (CSRF) state token returned by the provider does not
    /// match the one sent at authorization time. Maps to <c>OAuthError.stateMismatch</c>.
    /// </summary>
    StateMismatch = 1,

    /// <summary>
    /// The code→token POST to the provider failed (4xx/5xx or network error).
    /// Maps to <c>OAuthError.exchangeFailed</c>.
    /// </summary>
    TokenExchangeFailed = 2,

    /// <summary>
    /// The callback carried unexpected/missing parameters (no code, no state,
    /// unrecognised provider error). Maps to <c>OAuthError.invalidCallback</c>.
    /// </summary>
    InvalidCallback = 3
}
