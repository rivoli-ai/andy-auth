using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Owns the lifecycle of <see cref="OAuthAuthorization"/> records:
/// creation at authorize time, structured callback classification, state
/// transitions, and crash-reconciliation status queries.
/// <para>
/// SM.2.2 (rivoli-ai/conductor#2004): the three terminal failure classes
/// user_denied / state_mismatch / token_exchange_failed are classified here,
/// not inferred ad-hoc from redirect URL parameters, so Conductor's SM.8
/// <c>OAuthFlowState</c> always receives a typed discriminator rather than
/// an opaque callback URL.
/// </para>
/// <para>
/// State-machine invariant (enforced by
/// <see cref="TransitionAsync"/>):
/// <list type="bullet">
/// <item><c>Pending → Completed | Failed | Expired</c> — allowed.</item>
/// <item>Any transition FROM a terminal state — rejected (409 idempotency).</item>
/// </list>
/// </para>
/// <para>
/// Orphaned authorization: a Pending record whose <see cref="OAuthAuthorization.ExpiresAt"/>
/// has passed is automatically transitioned to Expired on the first status
/// query so clients that relaunched after a crash never see an ambiguous
/// "still pending" for an authorization that will never complete.
/// </para>
/// </summary>
public class OAuthAuthorizationService
{
    /// <summary>
    /// Default TTL for a pending authorization (matching typical provider TTLs).
    /// </summary>
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(10);

    private readonly ApplicationDbContext _db;
    private readonly ILogger<OAuthAuthorizationService> _logger;

    public OAuthAuthorizationService(ApplicationDbContext db, ILogger<OAuthAuthorizationService> logger)
    {
        _db = db;
        _logger = logger;
    }

    // ── creation ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Records a new in-flight authorization at broker /authorize time.
    /// Returns the <see cref="OAuthAuthorization.AuthorizationId"/> vended to
    /// the caller (embedded in the deep-link / callback state).
    /// </summary>
    /// <param name="provider">Provider key, e.g. "github".</param>
    /// <param name="rawStateToken">The raw anti-forgery state token sent to the provider.
    /// Stored as a SHA-256 hash — never the raw value.</param>
    /// <param name="subjectId">Optional andy-auth user ID when the caller is already signed in.</param>
    /// <param name="ttl">Override TTL. Defaults to <see cref="DefaultTtl"/>.</param>
    public async Task<OAuthAuthorization> CreateAsync(
        string provider,
        string rawStateToken,
        string? subjectId = null,
        TimeSpan? ttl = null)
    {
        var authorization = new OAuthAuthorization
        {
            Provider = provider,
            SubjectId = subjectId,
            StateTokenHash = HashStateToken(rawStateToken),
            State = OAuthAuthorizationState.Pending,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(ttl ?? DefaultTtl)
        };

        _db.OAuthAuthorizations.Add(authorization);
        await _db.SaveChangesAsync();

        _logger.LogInformation(
            "[SM.2.2] Created OAuth authorization {AuthId} for provider {Provider} (subject={Subject})",
            authorization.AuthorizationId, provider, subjectId ?? "<anonymous>");

        return authorization;
    }

    // ── callback classification ───────────────────────────────────────────────

    /// <summary>
    /// Classifies the callback response from the provider and transitions the
    /// authorization to the appropriate terminal state.
    /// </summary>
    /// <param name="authorizationId">The <see cref="OAuthAuthorization.AuthorizationId"/> embedded in the callback.</param>
    /// <param name="providerError">The <c>error</c> query parameter from the provider, if any.</param>
    /// <param name="returnedStateToken">The raw <c>state</c> query parameter returned by the provider, if any.</param>
    /// <param name="codePresent">True when the callback includes an <c>code</c> parameter.</param>
    /// <param name="tokenExchangeSuccess">
    /// True when the code→token POST to the provider succeeded. Only evaluated when
    /// <paramref name="codePresent"/> is true. Callers that have not yet attempted the
    /// exchange must pass <c>null</c> here and call
    /// <see cref="MarkTokenExchangeResultAsync"/> separately.
    /// </param>
    /// <param name="tokenExchangeDetail">Optional detail string for a failed token exchange.</param>
    /// <param name="connectionId">On successful exchange, the connection identifier created by the consuming service.</param>
    /// <returns>The classified <see cref="CallbackClassification"/> for the callback.</returns>
    public async Task<CallbackClassification> ClassifyCallbackAsync(
        Guid authorizationId,
        string? providerError,
        string? returnedStateToken,
        bool codePresent,
        bool? tokenExchangeSuccess,
        string? tokenExchangeDetail = null,
        string? connectionId = null)
    {
        var auth = await _db.OAuthAuthorizations
            .FirstOrDefaultAsync(a => a.AuthorizationId == authorizationId);

        if (auth == null)
        {
            _logger.LogWarning("[SM.2.2] Callback for unknown authorizationId {AuthId}", authorizationId);
            return new CallbackClassification(CallbackResult.InvalidCallback, null,
                "Authorization not found");
        }

        // ── idempotency guard: already-terminal record ────────────────────────
        if (auth.IsTerminal)
        {
            _logger.LogWarning(
                "[SM.2.2] Callback for already-terminal authorization {AuthId} (state={State}). Returning existing outcome.",
                authorizationId, auth.State);
            return MapTerminalStateToClassification(auth);
        }

        // ── expiry check ──────────────────────────────────────────────────────
        if (auth.IsStaleAndPending)
        {
            return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Expired,
                OAuthFailureReason.InvalidCallback,
                "Authorization expired before callback was received",
                new CallbackClassification(CallbackResult.InvalidCallback, authorizationId,
                    "Authorization expired"));
        }

        // ── 1. user_denied: provider explicitly signalled access_denied ───────
        if (string.Equals(providerError, "access_denied", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("[SM.2.2] Auth {AuthId}: classified as user_denied", authorizationId);
            return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
                OAuthFailureReason.UserDenied,
                "Provider returned error=access_denied",
                new CallbackClassification(CallbackResult.UserDenied, authorizationId,
                    "User denied access"));
        }

        // ── 2. other provider error (not access_denied, not success) ──────────
        if (!string.IsNullOrEmpty(providerError))
        {
            _logger.LogWarning("[SM.2.2] Auth {AuthId}: provider error {Error}", authorizationId, providerError);
            return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
                OAuthFailureReason.InvalidCallback,
                $"Provider returned error={providerError}",
                new CallbackClassification(CallbackResult.InvalidCallback, authorizationId,
                    $"Provider error: {providerError}"));
        }

        // ── 3. state_mismatch (CSRF): state token returned does not match ─────
        if (!string.IsNullOrEmpty(auth.StateTokenHash) && returnedStateToken != null)
        {
            if (!VerifyStateToken(returnedStateToken, auth.StateTokenHash))
            {
                _logger.LogWarning("[SM.2.2] Auth {AuthId}: state mismatch", authorizationId);
                return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
                    OAuthFailureReason.StateMismatch,
                    "CSRF anti-forgery state token mismatch",
                    new CallbackClassification(CallbackResult.StateMismatch, authorizationId,
                        "Anti-forgery state token mismatch"));
            }
        }
        else if (returnedStateToken == null && auth.StateTokenHash != null)
        {
            // Provider sent no state back at all — treat as CSRF/mismatch.
            return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
                OAuthFailureReason.StateMismatch,
                "No state token returned by provider",
                new CallbackClassification(CallbackResult.StateMismatch, authorizationId,
                    "Provider did not return state token"));
        }

        // ── 4. no code in callback ────────────────────────────────────────────
        if (!codePresent)
        {
            return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
                OAuthFailureReason.InvalidCallback,
                "Callback contained no authorization code",
                new CallbackClassification(CallbackResult.InvalidCallback, authorizationId,
                    "No authorization code in callback"));
        }

        // ── 5. token exchange result (if the caller resolved it synchronously) ─
        if (tokenExchangeSuccess.HasValue)
        {
            if (tokenExchangeSuccess.Value)
            {
                auth.ConnectionId = connectionId;
                _logger.LogInformation("[SM.2.2] Auth {AuthId}: completed successfully", authorizationId);
                return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Completed, null, null,
                    new CallbackClassification(CallbackResult.Success, authorizationId, null));
            }
            else
            {
                _logger.LogWarning("[SM.2.2] Auth {AuthId}: token_exchange_failed ({Detail})",
                    authorizationId, tokenExchangeDetail);
                return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
                    OAuthFailureReason.TokenExchangeFailed,
                    tokenExchangeDetail ?? "Token exchange POST to provider failed",
                    new CallbackClassification(CallbackResult.TokenExchangeFailed, authorizationId,
                        tokenExchangeDetail ?? "Token exchange failed"));
            }
        }

        // Exchange is pending — record remains Pending until the caller invokes
        // MarkTokenExchangeResultAsync.  Return a provisional success indicating
        // code was present and state was valid.
        return new CallbackClassification(CallbackResult.ExchangePending, authorizationId,
            "Authorization code received; exchange in progress");
    }

    /// <summary>
    /// Records the outcome of a code→token POST to the provider after the
    /// callback has already been received. Called when exchange is asynchronous.
    /// </summary>
    public async Task<CallbackClassification> MarkTokenExchangeResultAsync(
        Guid authorizationId,
        bool success,
        string? detail = null,
        string? connectionId = null)
    {
        var auth = await _db.OAuthAuthorizations
            .FirstOrDefaultAsync(a => a.AuthorizationId == authorizationId);

        if (auth == null)
        {
            return new CallbackClassification(CallbackResult.InvalidCallback, null,
                "Authorization not found");
        }

        if (auth.IsTerminal)
        {
            // 409-like idempotency: return existing terminal outcome.
            return MapTerminalStateToClassification(auth);
        }

        if (success)
        {
            auth.ConnectionId = connectionId;
            return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Completed, null, null,
                new CallbackClassification(CallbackResult.Success, authorizationId, null));
        }

        return await TerminalTransitionAsync(auth, OAuthAuthorizationState.Failed,
            OAuthFailureReason.TokenExchangeFailed,
            detail ?? "Token exchange POST to provider failed",
            new CallbackClassification(CallbackResult.TokenExchangeFailed, authorizationId, detail));
    }

    // ── ownership / capability lookup ─────────────────────────────────────────

    /// <summary>
    /// Returns the minimal descriptor (provider + initiating subject) needed to
    /// authorize a callback mutation or status read, without mutating the record
    /// (no lazy expiry). Returns <c>null</c> when the record does not exist.
    /// <para>
    /// Issue #123: the controller loads this first so it can bind the callback
    /// capability to the record's <see cref="OAuthAuthorization.Provider"/> and
    /// verify record ownership against the caller's subject, before any state
    /// transition is attempted.
    /// </para>
    /// </summary>
    public async Task<OAuthAuthorizationDescriptor?> GetDescriptorAsync(Guid authorizationId)
    {
        var auth = await _db.OAuthAuthorizations
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.AuthorizationId == authorizationId);

        if (auth == null)
            return null;

        return new OAuthAuthorizationDescriptor(auth.AuthorizationId, auth.Provider, auth.SubjectId);
    }

    // ── status query (crash reconciliation) ──────────────────────────────────

    /// <summary>
    /// Returns the authoritative state of an authorization for crash-reconciliation
    /// queries. Orphaned Pending records past their expiry are promoted to Expired.
    /// Returns <c>null</c> when the record does not exist.
    /// </summary>
    public async Task<OAuthAuthorizationStatus?> GetStatusAsync(Guid authorizationId)
    {
        var auth = await _db.OAuthAuthorizations
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.AuthorizationId == authorizationId);

        if (auth == null)
            return null;

        // Promote stale pending to Expired lazily.
        if (auth.IsStaleAndPending)
        {
            // Re-load with tracking to mutate.
            var tracked = await _db.OAuthAuthorizations
                .FirstOrDefaultAsync(a => a.AuthorizationId == authorizationId);
            if (tracked != null && tracked.IsStaleAndPending)
            {
                await TransitionAsync(tracked, OAuthAuthorizationState.Expired,
                    OAuthFailureReason.InvalidCallback,
                    "Authorization expired (orphaned — never received callback)");
                auth = tracked;
            }
        }

        return MapToStatus(auth);
    }

    // ── cleanup ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Marks all Pending authorizations past their expiry as Expired.
    /// Intended to be called periodically by a background cleanup job.
    /// Returns the number of records transitioned.
    /// </summary>
    public async Task<int> ExpireStaleAuthorizationsAsync()
    {
        var cutoff = DateTime.UtcNow;
        var stale = await _db.OAuthAuthorizations
            .Where(a => a.State == OAuthAuthorizationState.Pending && a.ExpiresAt <= cutoff)
            .ToListAsync();

        foreach (var auth in stale)
        {
            auth.State = OAuthAuthorizationState.Expired;
            auth.FailureReason = OAuthFailureReason.InvalidCallback;
            auth.FailureDetail = "Authorization expired (cleaned up by background job)";
            auth.CompletedAt = DateTime.UtcNow;
        }

        if (stale.Count > 0)
        {
            await _db.SaveChangesAsync();
            _logger.LogInformation("[SM.2.2] Expired {Count} stale OAuth authorizations", stale.Count);
        }

        return stale.Count;
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Applies a terminal transition and returns the caller's intended outcome on
    /// success, or — when the record is already terminal or a concurrent writer
    /// won the race — the authoritative existing terminal outcome. This is the
    /// single funnel through which the callback classifier reaches a terminal
    /// state so that idempotency and concurrency reconciliation are handled once.
    /// </summary>
    private async Task<CallbackClassification> TerminalTransitionAsync(
        OAuthAuthorization auth,
        OAuthAuthorizationState targetState,
        OAuthFailureReason? reason,
        string? detail,
        CallbackClassification onWin)
    {
        var won = await TransitionAsync(auth, targetState, reason, detail);
        return won ? onWin : MapTerminalStateToClassification(auth);
    }

    /// <summary>
    /// Attempts a single Pending → terminal transition. Returns <c>true</c> when
    /// this call applied the transition, <c>false</c> when the record was already
    /// terminal or a concurrent writer committed a terminal state first (the
    /// tracked entity is reloaded to the winning state on that path).
    /// <para>
    /// Atomicity (issue #123): the <see cref="OAuthAuthorization.ConcurrencyToken"/>
    /// is rotated on every write, so two racing terminal saves cannot both
    /// commit — the loser's UPDATE matches zero rows and EF raises
    /// <see cref="DbUpdateConcurrencyException"/>, which we reconcile to the
    /// winner rather than overwrite.
    /// </para>
    /// </summary>
    private async Task<bool> TransitionAsync(
        OAuthAuthorization auth,
        OAuthAuthorizationState targetState,
        OAuthFailureReason? reason,
        string? detail)
    {
        if (auth.IsTerminal)
        {
            // Already terminal — silently ignore (idempotency).
            _logger.LogDebug(
                "[SM.2.2] Ignoring transition for already-terminal auth {AuthId} (current={State})",
                auth.AuthorizationId, auth.State);
            return false;
        }

        auth.State = targetState;
        auth.FailureReason = reason;
        auth.FailureDetail = detail;
        auth.CompletedAt = DateTime.UtcNow;
        auth.ConcurrencyToken = Guid.NewGuid();

        try
        {
            await _db.SaveChangesAsync();
            return true;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // Lost the race to a concurrent terminal writer. Reload the winning
            // state into the tracked entity so callers surface the authoritative
            // outcome (409 idempotency) instead of clobbering it.
            var entry = ex.Entries.SingleOrDefault();
            if (entry != null)
            {
                await entry.ReloadAsync();
            }

            _logger.LogWarning(
                "[#123] Concurrent terminal transition for auth {AuthId} lost the race; " +
                "reconciled to authoritative state {State}.",
                auth.AuthorizationId, auth.State);

            return false;
        }
    }

    private static OAuthAuthorizationStatus MapToStatus(OAuthAuthorization auth)
    {
        return new OAuthAuthorizationStatus
        {
            AuthorizationId = auth.AuthorizationId,
            SubjectId = auth.SubjectId,
            State = auth.State,
            FailureReason = auth.FailureReason,
            FailureDetail = auth.FailureDetail,
            CreatedAt = auth.CreatedAt,
            ExpiresAt = auth.ExpiresAt,
            CompletedAt = auth.CompletedAt,
            ConnectionId = auth.ConnectionId
        };
    }

    private static CallbackClassification MapTerminalStateToClassification(OAuthAuthorization auth)
    {
        var result = auth.State switch
        {
            OAuthAuthorizationState.Completed => CallbackResult.Success,
            OAuthAuthorizationState.Expired => CallbackResult.InvalidCallback,
            OAuthAuthorizationState.Failed => auth.FailureReason switch
            {
                OAuthFailureReason.UserDenied => CallbackResult.UserDenied,
                OAuthFailureReason.StateMismatch => CallbackResult.StateMismatch,
                OAuthFailureReason.TokenExchangeFailed => CallbackResult.TokenExchangeFailed,
                _ => CallbackResult.InvalidCallback
            },
            _ => CallbackResult.ExchangePending
        };

        return new CallbackClassification(result, auth.AuthorizationId, auth.FailureDetail);
    }

    private static string HashStateToken(string raw)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static bool VerifyStateToken(string raw, string expectedHash)
    {
        var actualHash = HashStateToken(raw);
        return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// The result of classifying an OAuth callback. Returned by
/// <see cref="OAuthAuthorizationService.ClassifyCallbackAsync"/>.
/// </summary>
public enum CallbackResult
{
    /// <summary>Token exchange succeeded.</summary>
    Success,

    /// <summary>User explicitly denied the authorization at the provider.</summary>
    UserDenied,

    /// <summary>CSRF anti-forgery state token mismatch.</summary>
    StateMismatch,

    /// <summary>Code→token POST to provider failed.</summary>
    TokenExchangeFailed,

    /// <summary>Callback carried invalid/unexpected parameters.</summary>
    InvalidCallback,

    /// <summary>Code received; exchange has not been resolved yet.</summary>
    ExchangePending
}

/// <summary>
/// The result of a single OAuth callback classification, returned to callers of
/// <see cref="OAuthAuthorizationService.ClassifyCallbackAsync"/>.
/// </summary>
public record CallbackClassification(
    CallbackResult Result,
    Guid? AuthorizationId,
    string? Detail);

/// <summary>
/// Minimal, side-effect-free view of an authorization used by the controller to
/// authorize a callback mutation or status read before any state transition:
/// the <see cref="Provider"/> the callback capability must be bound to, and the
/// <see cref="SubjectId"/> that owns the record (issue #123).
/// </summary>
public record OAuthAuthorizationDescriptor(
    Guid AuthorizationId,
    string Provider,
    string? SubjectId);

/// <summary>
/// Authoritative authorization status for the crash-reconciliation endpoint.
/// </summary>
public record OAuthAuthorizationStatus
{
    public Guid AuthorizationId { get; init; }

    /// <summary>
    /// The andy-auth subject that initiated this authorization, used by the
    /// controller to enforce record ownership on status reads (issue #123).
    /// Null for guest / pre-login broker flows.
    /// </summary>
    public string? SubjectId { get; init; }

    public OAuthAuthorizationState State { get; init; }
    public OAuthFailureReason? FailureReason { get; init; }
    public string? FailureDetail { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public DateTime? CompletedAt { get; init; }
    public string? ConnectionId { get; init; }
}
