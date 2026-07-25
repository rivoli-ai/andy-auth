using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Controllers.Api;

/// <summary>
/// SM.2.2 (rivoli-ai/conductor#2004) — OAuth broker callback taxonomy +
/// crash-reconciliation endpoints.
/// <para>
/// <list type="bullet">
/// <item>
///   <c>POST /auth/oauth/authorizations</c> — record a new in-flight authorization
///   at broker /authorize time, returning the <c>authorizationId</c> to embed in
///   the deep-link callback state.
/// </item>
/// <item>
///   <c>POST /auth/oauth/authorizations/{id}/callback</c> — classify the provider
///   callback and persist the terminal outcome. Returns a structured
///   <see cref="CallbackOutcomeDto"/> instead of an opaque redirect error so
///   Conductor can map directly to <c>OAuthError</c> cases.
/// </item>
/// <item>
///   <c>GET /auth/oauth/authorizations/{id}</c> — crash-reconciliation endpoint.
///   Returns the authoritative state of the authorization so a client that
///   relaunched after a crash mid-exchange can resolve its
///   <c>OAuthFlowState.exchangingCode</c> marker to a known terminal outcome
///   rather than spinning forever. Pending records past their TTL are lazily
///   promoted to Expired on this call.
/// </item>
/// </list>
/// </para>
/// </summary>
[ApiController]
[Route("auth/oauth/authorizations")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Produces("application/json")]
public class OAuthAuthorizationsController : ControllerBase
{
    /// <summary>
    /// Request header carrying the signed one-time callback capability minted at
    /// /authorize time. Presented by the callback handler in lieu of a bearer
    /// token (the provider redirect carries no bearer). Issue #123.
    /// </summary>
    public const string CapabilityHeader = "X-OAuth-Callback-Token";

    /// <summary>
    /// Dedicated OAuth scope identifying the machine <b>broker</b> service
    /// identity (issue #123). Granted only to the client-credentials broker
    /// client — NOT to human users, and deliberately independent of the human
    /// <c>Admin</c> role. A principal carrying this scope may drive callback
    /// mutations without a capability and read any authorization's status. See
    /// <c>Program.cs</c> where the scope is registered.
    /// </summary>
    public const string BrokerScope = "andy_auth:oauth_broker";

    private readonly OAuthAuthorizationService _service;
    private readonly OAuthCallbackCapabilityService _capabilities;
    private readonly ILogger<OAuthAuthorizationsController> _logger;

    public OAuthAuthorizationsController(
        OAuthAuthorizationService service,
        OAuthCallbackCapabilityService capabilities,
        ILogger<OAuthAuthorizationsController> logger)
    {
        _service = service;
        _capabilities = capabilities;
        _logger = logger;
    }

    // ── create ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Records a new in-flight authorization at broker /authorize time.
    /// The caller embeds the returned <c>authorizationId</c> in the OAuth state
    /// parameter sent to the provider so the callback handler can look it up.
    /// </summary>
    /// <remarks>
    /// Auth: bearer token (the user must be signed in to initiate a broker flow).
    /// </remarks>
    [HttpPost]
    [ProducesResponseType(typeof(AuthorizationCreatedDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Create([FromBody] CreateAuthorizationRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (string.IsNullOrWhiteSpace(request.Provider))
            return BadRequest(new { error = "provider is required" });

        if (string.IsNullOrWhiteSpace(request.StateToken))
            return BadRequest(new { error = "state_token is required" });

        var subjectId = User.FindFirst("sub")?.Value;
        var auth = await _service.CreateAsync(request.Provider, request.StateToken, subjectId);

        // Mint the signed, narrowly-scoped callback capability bound to this
        // authorization id + provider (issue #123). The caller embeds it in the
        // deep-link and presents it via the X-OAuth-Callback-Token header on the
        // anonymous provider callback, so knowledge of the UUID alone can no
        // longer drive a terminal transition.
        var callbackToken = _capabilities.Issue(auth.AuthorizationId, auth.Provider, auth.ExpiresAt);

        var dto = new AuthorizationCreatedDto
        {
            AuthorizationId = auth.AuthorizationId,
            ExpiresAt = auth.ExpiresAt,
            CallbackToken = callbackToken
        };

        return CreatedAtAction(nameof(GetStatus), new { id = auth.AuthorizationId }, dto);
    }

    // ── callback classification ───────────────────────────────────────────────

    /// <summary>
    /// Classifies the provider callback and persists the terminal outcome.
    /// Returns a structured discriminator so Conductor can map directly to
    /// <c>OAuthError</c> cases — no opaque redirect URL parsing required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>result</c> field in the response maps to Conductor's <c>OAuthError</c>:
    /// <list type="bullet">
    /// <item><c>success</c> — no error; connection established.</item>
    /// <item><c>user_denied</c> → <c>OAuthError.permissionDenied</c></item>
    /// <item><c>state_mismatch</c> → <c>OAuthError.stateMismatch</c></item>
    /// <item><c>token_exchange_failed</c> → <c>OAuthError.exchangeFailed</c></item>
    /// <item><c>invalid_callback</c> → <c>OAuthError.invalidCallback</c></item>
    /// </list>
    /// </para>
    /// <para>
    /// 409 Conflict: replaying a callback for an already-terminal authorization
    /// returns the existing outcome rather than throwing, allowing idempotent
    /// retries.
    /// </para>
    /// </remarks>
    [HttpPost("{id:guid}/callback")]
    [AllowAnonymous] // Callback arrives from a browser redirect, no bearer token in flight.
    [ProducesResponseType(typeof(CallbackOutcomeDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(CallbackOutcomeDto), StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RecordCallback(
        Guid id,
        [FromBody] RecordCallbackRequest request)
    {
        // Load the record first so the capability can be bound to its provider
        // and the caller authorized before any state transition (issue #123).
        var descriptor = await _service.GetDescriptorAsync(id);
        if (descriptor == null)
            return NotFound(new { error = "Authorization not found" });

        if (!TryAuthorizeCallbackMutation(id, descriptor.Provider, out var failure))
            return failure!;

        var classification = await _service.ClassifyCallbackAsync(
            authorizationId: id,
            providerError: request.ProviderError,
            returnedStateToken: request.ReturnedStateToken,
            codePresent: request.CodePresent,
            tokenExchangeSuccess: request.TokenExchangeSuccess,
            tokenExchangeDetail: request.TokenExchangeDetail,
            connectionId: request.ConnectionId);

        var dto = MapClassificationToDto(classification);

        // 200 when THIS call committed the processing; 409 when the outcome came
        // from an already-terminal record — an idempotent replay, or the loser of
        // a concurrent terminal race reconciled to the winner's outcome. Derived
        // from the transition result, not a pre-read, so it holds under
        // concurrency (issue #123).
        var statusCode = classification.Committed
            ? StatusCodes.Status200OK
            : StatusCodes.Status409Conflict;

        _logger.LogInformation(
            "[SM.2.2] Callback recorded for auth {AuthId}: result={Result} status={Status}",
            id, dto.Result, statusCode);

        return StatusCode(statusCode, dto);
    }

    /// <summary>
    /// Marks the result of an asynchronous code→token exchange.
    /// Idempotent: replaying for an already-terminal authorization returns
    /// the existing outcome with 409 Conflict so callers can detect the
    /// "stale projection" case.
    /// </summary>
    [HttpPost("{id:guid}/exchange-result")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(CallbackOutcomeDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(CallbackOutcomeDto), StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> MarkExchangeResult(
        Guid id,
        [FromBody] MarkExchangeResultRequest request)
    {
        var descriptor = await _service.GetDescriptorAsync(id);
        if (descriptor == null)
            return NotFound(new { error = "Authorization not found" });

        if (!TryAuthorizeCallbackMutation(id, descriptor.Provider, out var failure))
            return failure!;

        var classification = await _service.MarkTokenExchangeResultAsync(
            id,
            request.Success,
            request.Detail,
            request.ConnectionId);

        var dto = MapClassificationToDto(classification);

        // 409 when the outcome came from an already-terminal record (idempotent
        // replay or reconciled concurrent loser); 200 when this call committed.
        var httpStatus = classification.Committed
            ? StatusCodes.Status200OK
            : StatusCodes.Status409Conflict;

        return StatusCode(httpStatus, dto);
    }

    // ── status / crash-reconciliation ─────────────────────────────────────────

    /// <summary>
    /// Returns the authoritative state of an authorization.
    /// <para>
    /// A client that relaunched after a crash mid-exchange calls this endpoint
    /// with the <c>authorizationId</c> persisted in its durable marker
    /// (SM.8 <c>ObservationMarker&lt;Authorization&gt;</c>) to reconcile its
    /// <c>OAuthFlowState</c> to the true terminal outcome rather than spinning
    /// forever in <c>.exchangingCode</c>.
    /// </para>
    /// <para>
    /// Orphaned Pending records past their <c>expiresAt</c> are lazily promoted
    /// to <c>expired</c> on this call — the client never sees an ambiguous
    /// "still pending" for an authorization that will never complete.
    /// </para>
    /// </summary>
    /// <response code="200">Authoritative authorization status.</response>
    /// <response code="404">No authorization with the given ID exists.</response>
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(AuthorizationStatusDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetStatus(Guid id)
    {
        var status = await _service.GetStatusAsync(id);

        if (status == null)
            return NotFound(new { error = "Authorization not found" });

        // Ownership (issue #123): only the initiating subject or an authorized
        // service identity may read the authoritative status. Knowledge of the
        // UUID is not sufficient. Return 403 (not 404) — the caller is
        // authenticated (class-level [Authorize]) but not entitled to this record.
        if (!IsAuthorizedForRecord(status.SubjectId))
        {
            _logger.LogWarning(
                "[#123] Subject {Subject} denied status read for auth {AuthId} owned by {Owner}",
                User.FindFirst("sub")?.Value ?? "<none>", id, status.SubjectId ?? "<none>");
            return Forbid();
        }

        var dto = new AuthorizationStatusDto
        {
            AuthorizationId = status.AuthorizationId,
            State = MapStateToString(status.State),
            FailureReason = MapFailureReasonToString(status.FailureReason),
            FailureDetail = status.FailureDetail,
            CreatedAt = status.CreatedAt,
            ExpiresAt = status.ExpiresAt,
            CompletedAt = status.CompletedAt,
            ConnectionId = status.ConnectionId
        };

        return Ok(dto);
    }

    // ── authorization helpers (issue #123) ─────────────────────────────────────

    /// <summary>
    /// Authorizes a callback mutation. Succeeds when the caller presents a valid
    /// capability token bound to this authorization id + provider, OR (absent a
    /// capability) authenticates as an authorized broker/service identity.
    /// Knowledge of the authorization UUID alone never suffices.
    /// </summary>
    /// <returns>
    /// <c>true</c> when authorized; otherwise <c>false</c> with <paramref name="failure"/>
    /// set to a 403 (a capability was presented but is invalid/expired/mis-bound —
    /// tampering) or 401 (no capability and no service identity).
    /// </returns>
    private bool TryAuthorizeCallbackMutation(Guid id, string provider, out IActionResult? failure)
    {
        failure = null;

        var presentedToken = Request.Headers[CapabilityHeader].FirstOrDefault();
        if (!string.IsNullOrEmpty(presentedToken))
        {
            if (_capabilities.Validate(presentedToken, id, provider))
                return true;

            _logger.LogWarning(
                "[#123] Rejected callback mutation for auth {AuthId}: capability token invalid, " +
                "expired, or bound to a different authorization/provider.", id);
            failure = StatusCode(StatusCodes.Status403Forbidden, new { error = "invalid_capability" });
            return false;
        }

        if (IsAuthorizedServiceIdentity())
            return true;

        _logger.LogWarning(
            "[#123] Rejected callback mutation for auth {AuthId}: no capability token and caller " +
            "is not an authorized service identity.", id);
        failure = StatusCode(StatusCodes.Status401Unauthorized,
            new { error = "callback_authorization_required" });
        return false;
    }

    /// <summary>
    /// True when the caller is the initiating subject of the record or an
    /// authorized service identity. Used to gate status reads (issue #123).
    /// </summary>
    private bool IsAuthorizedForRecord(string? ownerSubjectId)
    {
        var callerSubject = User.FindFirst("sub")?.Value;
        if (!string.IsNullOrEmpty(ownerSubjectId)
            && string.Equals(ownerSubjectId, callerSubject, StringComparison.Ordinal))
        {
            return true;
        }

        return IsAuthorizedServiceIdentity();
    }

    /// <summary>
    /// True when the authenticated principal is the machine <b>broker</b> service
    /// identity — i.e. it carries the dedicated <see cref="BrokerScope"/> OAuth
    /// scope (issue #123). This is deliberately distinct from the human
    /// <c>Admin</c> role: a person with admin rights is not a broker and must not
    /// be able to read arbitrary authorization status or forge terminal
    /// transitions without a signed capability. The scope is granted only to the
    /// client-credentials (M2M) broker client.
    /// </summary>
    private bool IsAuthorizedServiceIdentity()
        => User.Identity?.IsAuthenticated == true && HasBrokerScope();

    /// <summary>
    /// True when the principal's granted scopes include <see cref="BrokerScope"/>.
    /// Handles both a space-delimited <c>scope</c> claim (JWT / RFC 8693 access
    /// token) and OpenIddict's normalized private scope claims.
    /// </summary>
    private bool HasBrokerScope()
    {
        foreach (var claim in User.FindAll("scope"))
        {
            if (claim.Value
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Contains(BrokerScope, StringComparer.Ordinal))
            {
                return true;
            }
        }

        return User.HasScope(BrokerScope);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static CallbackOutcomeDto MapClassificationToDto(CallbackClassification classification)
    {
        var resultString = classification.Result switch
        {
            CallbackResult.Success => "success",
            CallbackResult.UserDenied => "user_denied",
            CallbackResult.StateMismatch => "state_mismatch",
            CallbackResult.TokenExchangeFailed => "token_exchange_failed",
            CallbackResult.ExchangePending => "exchange_pending",
            _ => "invalid_callback"
        };

        return new CallbackOutcomeDto
        {
            Result = resultString,
            AuthorizationId = classification.AuthorizationId,
            Detail = classification.Detail
        };
    }

    private static string MapStateToString(OAuthAuthorizationState state) => state switch
    {
        OAuthAuthorizationState.Pending => "pending",
        OAuthAuthorizationState.Completed => "completed",
        OAuthAuthorizationState.Failed => "failed",
        OAuthAuthorizationState.Expired => "expired",
        _ => "unknown"
    };

    private static string? MapFailureReasonToString(OAuthFailureReason? reason) => reason switch
    {
        OAuthFailureReason.UserDenied => "user_denied",
        OAuthFailureReason.StateMismatch => "state_mismatch",
        OAuthFailureReason.TokenExchangeFailed => "token_exchange_failed",
        OAuthFailureReason.InvalidCallback => "invalid_callback",
        null => null,
        _ => null
    };
}

// ── Request / Response DTOs ─────────────────────────────────────────────────

/// <summary>Request body for POST /auth/oauth/authorizations.</summary>
public class CreateAuthorizationRequest
{
    /// <summary>The external OAuth provider key (e.g. "github", "gitlab").</summary>
    [JsonPropertyName("provider")]
    public string Provider { get; set; } = null!;

    /// <summary>
    /// The raw anti-forgery state token that will be sent to the provider.
    /// Stored as a SHA-256 hash server-side — never persisted in plaintext.
    /// </summary>
    [JsonPropertyName("state_token")]
    public string StateToken { get; set; } = null!;
}

/// <summary>Response body for POST /auth/oauth/authorizations.</summary>
public class AuthorizationCreatedDto
{
    /// <summary>
    /// The authorization ID to embed in the OAuth state parameter sent to
    /// the provider and in the deep-link returned to the client.
    /// </summary>
    [JsonPropertyName("authorizationId")]
    public Guid AuthorizationId { get; set; }

    /// <summary>When the authorization expires if not completed (UTC).</summary>
    [JsonPropertyName("expiresAt")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Signed, narrowly-scoped one-time capability bound to this authorization id
    /// and provider (issue #123). The caller embeds it in the callback deep-link
    /// and presents it via the <c>X-OAuth-Callback-Token</c> header when driving
    /// the anonymous provider callback / exchange-result mutation, so knowledge of
    /// the authorization UUID alone can no longer authorize a terminal transition.
    /// </summary>
    [JsonPropertyName("callbackToken")]
    public string CallbackToken { get; set; } = null!;
}

/// <summary>Request body for POST /auth/oauth/authorizations/{id}/callback.</summary>
public class RecordCallbackRequest
{
    /// <summary>The <c>error</c> parameter returned by the provider, if any.</summary>
    [JsonPropertyName("provider_error")]
    public string? ProviderError { get; set; }

    /// <summary>The raw <c>state</c> parameter returned by the provider.</summary>
    [JsonPropertyName("returned_state_token")]
    public string? ReturnedStateToken { get; set; }

    /// <summary>Whether the callback included an authorization <c>code</c> parameter.</summary>
    [JsonPropertyName("code_present")]
    public bool CodePresent { get; set; }

    /// <summary>
    /// Whether the code→token exchange succeeded. Null when the caller has not
    /// yet attempted the exchange and will call /exchange-result separately.
    /// </summary>
    [JsonPropertyName("token_exchange_success")]
    public bool? TokenExchangeSuccess { get; set; }

    /// <summary>Optional detail string for a failed token exchange.</summary>
    [JsonPropertyName("token_exchange_detail")]
    public string? TokenExchangeDetail { get; set; }

    /// <summary>Connection identifier created by the consuming service on success.</summary>
    [JsonPropertyName("connection_id")]
    public string? ConnectionId { get; set; }
}

/// <summary>Request body for POST /auth/oauth/authorizations/{id}/exchange-result.</summary>
public class MarkExchangeResultRequest
{
    /// <summary>True when the code→token exchange succeeded.</summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>Optional detail for a failed exchange.</summary>
    [JsonPropertyName("detail")]
    public string? Detail { get; set; }

    /// <summary>Connection identifier on success.</summary>
    [JsonPropertyName("connection_id")]
    public string? ConnectionId { get; set; }
}

/// <summary>
/// SM.2.2 structured callback outcome discriminator.
/// Returned by <c>POST /auth/oauth/authorizations/{id}/callback</c>.
/// </summary>
public class CallbackOutcomeDto
{
    /// <summary>
    /// Structured result discriminator. One of:
    /// <c>success</c>, <c>user_denied</c>, <c>state_mismatch</c>,
    /// <c>token_exchange_failed</c>, <c>invalid_callback</c>, <c>exchange_pending</c>.
    /// <para>
    /// Conductor mapping:
    /// <list type="bullet">
    /// <item><c>success</c> → connection established, no error.</item>
    /// <item><c>user_denied</c> → <c>OAuthError.permissionDenied</c></item>
    /// <item><c>state_mismatch</c> → <c>OAuthError.stateMismatch</c></item>
    /// <item><c>token_exchange_failed</c> → <c>OAuthError.exchangeFailed</c></item>
    /// <item><c>invalid_callback</c> → <c>OAuthError.invalidCallback</c></item>
    /// </list>
    /// </para>
    /// </summary>
    [JsonPropertyName("result")]
    public string Result { get; set; } = null!;

    /// <summary>The authorization ID this outcome belongs to.</summary>
    [JsonPropertyName("authorizationId")]
    public Guid? AuthorizationId { get; set; }

    /// <summary>Human-readable detail. Never contains secrets.</summary>
    [JsonPropertyName("detail")]
    public string? Detail { get; set; }
}

/// <summary>
/// SM.2.2 authoritative authorization status for crash-reconciliation.
/// Returned by <c>GET /auth/oauth/authorizations/{id}</c>.
/// </summary>
public class AuthorizationStatusDto
{
    /// <summary>The authorization ID.</summary>
    [JsonPropertyName("authorizationId")]
    public Guid AuthorizationId { get; set; }

    /// <summary>
    /// Current lifecycle state. One of:
    /// <c>pending</c>, <c>completed</c>, <c>failed</c>, <c>expired</c>.
    /// </summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = null!;

    /// <summary>
    /// Failure reason when <c>state</c> is <c>failed</c>. One of:
    /// <c>user_denied</c>, <c>state_mismatch</c>, <c>token_exchange_failed</c>,
    /// <c>invalid_callback</c>. Null otherwise.
    /// </summary>
    [JsonPropertyName("failureReason")]
    public string? FailureReason { get; set; }

    /// <summary>Human-readable failure detail. Null on success.</summary>
    [JsonPropertyName("failureDetail")]
    public string? FailureDetail { get; set; }

    /// <summary>When the authorization was initiated (UTC).</summary>
    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; }

    /// <summary>When the authorization expires (UTC).</summary>
    [JsonPropertyName("expiresAt")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>When the authorization reached a terminal state (UTC). Null while pending.</summary>
    [JsonPropertyName("completedAt")]
    public DateTime? CompletedAt { get; set; }

    /// <summary>
    /// The connection ID created on successful exchange, when applicable.
    /// Null until the authorization reaches <c>completed</c> state.
    /// </summary>
    [JsonPropertyName("connectionId")]
    public string? ConnectionId { get; set; }
}
