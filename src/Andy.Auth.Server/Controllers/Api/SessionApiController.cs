using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Controllers.Api;

/// <summary>
/// SM.2.1 (rivoli-ai/conductor#2003 · epic #1975) — machine-readable session
/// truth + an explicit, unambiguous revocation signal for native clients.
/// <para>
/// Root cause this addresses (#1861 "all-red on launch"): today a transient 5xx
/// and a genuine 401/revocation are <b>conflated</b>, so Conductor signs the
/// user out on a momentary blip. This controller gives the client three cleanly
/// separated outcomes — 200 (truth), 410 (revoked, permanent → sign out), and
/// 401 (invalid token, permanent → sign out) — while transient failures are
/// reported as 503 <c>temporarily_unavailable</c> (→ retry) and never collapse
/// into a 401.
/// </para>
/// <para>
/// Authoritative channel: andy-auth has <b>no NATS/event bus</b>, so the
/// revocation signal is HTTP-pull. <c>GET /auth/session</c> is the authoritative
/// reconciliation endpoint, and 410 on this protected call is the §7.4 explicit
/// revocation push the SessionState reflector (SM.5) consumes instead of a
/// timeout/5xx heuristic.
/// </para>
/// </summary>
[ApiController]
[Route("auth")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Produces("application/json")]
public class SessionApiController : ControllerBase
{
    private readonly SessionService _sessionService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<SessionApiController> _logger;

    public SessionApiController(
        SessionService sessionService,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<SessionApiController> logger)
    {
        _sessionService = sessionService;
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    /// <summary>
    /// Returns the authoritative session truth for the bearer token.
    /// <list type="bullet">
    /// <item>200 <c>{authenticated:true, subject, sessionId, expiresAt, revoked:false}</c> — live session.</item>
    /// <item>410 Gone <c>{reason:"session_revoked"}</c> — the session was explicitly revoked (permanent → sign out).</item>
    /// <item>401 <c>{reason:"invalid_token"}</c> — token bound to an account that no longer exists / cannot sign in (permanent → sign out).</item>
    /// <item>200 <c>{authenticated:false, revoked:false}</c> — no active session (expired/none); a clean "not signed in", never a 500.</item>
    /// </list>
    /// A momentary backend/dependency failure surfaces as 503
    /// <c>temporarily_unavailable</c> (→ retry), distinct from the above.
    /// </summary>
    [HttpGet("session")]
    [ProducesResponseType(typeof(SessionTruthDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(SessionErrorDto), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(SessionErrorDto), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(SessionErrorDto), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> GetSession()
    {
        // OpenIddict's validation handler has already rejected structurally
        // invalid/expired tokens with a 401 before we get here, so a missing
        // subject means the token is well-formed but bound to nothing we trust.
        var subject = User.GetClaim(Claims.Subject);
        if (string.IsNullOrEmpty(subject))
        {
            return InvalidToken("The access token does not carry a subject.");
        }

        // The token's session id, when present, lets us answer about THIS exact
        // session rather than the subject's most-recent one.
        var sessionId = User.GetClaim("session_id");

        try
        {
            // Account-existence check first: a token bound to a deleted account
            // is a permanent 401 invalid_token, NOT a 5xx.
            var user = await _userManager.FindByIdAsync(subject);
            if (user == null || user.DeletedAt != null)
            {
                _logger.LogInformation(
                    "[SM.2.1] /auth/session: token subject {Subject} maps to no live account.", subject);
                return InvalidToken("The access token is bound to an account that no longer exists.");
            }

            if (!await _signInManager.CanSignInAsync(user))
            {
                _logger.LogInformation(
                    "[SM.2.1] /auth/session: subject {Subject} is no longer allowed to sign in.", subject);
                return InvalidToken("The account is no longer allowed to sign in.");
            }

            var truth = await _sessionService.ResolveSessionTruthAsync(subject, sessionId);

            if (truth.IsRevoked)
            {
                // 410 Gone is the explicit, unambiguous revocation signal.
                _logger.LogInformation(
                    "[SM.2.1] /auth/session: session {SessionId} for {Subject} is revoked ({Reason}).",
                    truth.SessionId, subject, truth.Reason ?? "session_revoked");
                return Revoked(truth);
            }

            var dto = new SessionTruthDto
            {
                Authenticated = truth.IsAuthenticated,
                Subject = truth.Subject ?? subject,
                SessionId = truth.SessionId,
                ExpiresAt = truth.ExpiresAt,
                Revoked = false
            };
            return Ok(dto);
        }
        catch (Exception ex)
        {
            // A dependency failure (DB/upstream) is TRANSIENT. It must surface as
            // 503 temporarily_unavailable so the client retries — it must NEVER
            // collapse into a 401/sign-out (the #1861 conflation guard).
            _logger.LogError(ex,
                "[SM.2.1] /auth/session: transient failure resolving session for subject; returning 503.");
            return TemporarilyUnavailable();
        }
    }

    private ObjectResult InvalidToken(string description)
    {
        Response.Headers.WWWAuthenticate =
            $"Bearer error=\"{SessionErrorCodes.InvalidToken}\", error_description=\"{description}\"";
        return StatusCode(StatusCodes.Status401Unauthorized, new SessionErrorDto
        {
            Reason = SessionErrorCodes.InvalidToken,
            Description = description
        });
    }

    private ObjectResult Revoked(SessionTruth truth)
    {
        return StatusCode(StatusCodes.Status410Gone, new SessionErrorDto
        {
            Reason = SessionErrorCodes.SessionRevoked,
            Description = truth.Reason
        });
    }

    private ObjectResult TemporarilyUnavailable()
    {
        // Advise a modest retry; the client classifies 503 as transient.
        Response.Headers.RetryAfter = "5";
        return StatusCode(StatusCodes.Status503ServiceUnavailable, new SessionErrorDto
        {
            Reason = SessionErrorCodes.TemporarilyUnavailable,
            Description = "The authentication service is momentarily unavailable. Retry shortly."
        });
    }
}
