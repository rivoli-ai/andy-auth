using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Establishes the server-side session before an Identity application cookie
/// is issued. This covers password, MFA, registration, and external sign-ins
/// through one cookie boundary instead of relying on a later page request.
/// </summary>
public sealed class InteractiveSessionCookieEvents : CookieAuthenticationEvents
{
    private readonly SessionService _sessionService;
    private readonly ILogger<InteractiveSessionCookieEvents> _logger;

    public InteractiveSessionCookieEvents(
        SessionService sessionService,
        ILogger<InteractiveSessionCookieEvents> logger)
    {
        _sessionService = sessionService;
        _logger = logger;
    }

    public override async Task SigningIn(CookieSigningInContext context)
    {
        var userId = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        var sessionId = context.Principal?.FindFirstValue(
            AndyAuthSignInManager.SessionIdClaimType);

        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(sessionId))
        {
            _logger.LogError(
                "Refusing to issue an application cookie without user and session identifiers");
            throw new InvalidOperationException(
                "An interactive authentication cookie requires user and session identifiers.");
        }

        var existing = await _sessionService.GetSessionAsync(sessionId);
        if (existing is not null)
        {
            // RefreshSignInAsync and security-stamp renewal deliberately retain
            // the same session id. They may refresh only the same active user's
            // cookie; a revoked or cross-user record must never be resurrected.
            if (!string.Equals(existing.UserId, userId, StringComparison.Ordinal) ||
                !await _sessionService.IsSessionValidAsync(existing))
            {
                _logger.LogWarning(
                    "Refusing to refresh invalid session {SessionId} for user {UserId}",
                    sessionId, userId);
                throw new InvalidOperationException(
                    "The interactive authentication session is no longer valid.");
            }

            return;
        }

        await _sessionService.CreateSessionAsync(
            userId,
            sessionId,
            context.HttpContext.Connection.RemoteIpAddress?.ToString(),
            context.HttpContext.Request.Headers.UserAgent.FirstOrDefault());
    }
}
