using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
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

    // .NET 10 stops the cookie handler redirecting to LoginPath for endpoints it
    // classifies as APIs (anything carrying IApiEndpointMetadata, which every
    // [ApiController] action does) and returns 401/403 instead. See
    // https://learn.microsoft.com/aspnet/core/breaking-changes/10/cookie-authentication-api-endpoints
    //
    // That default is right for our REST surface and WRONG for the OpenIddict
    // interactive endpoints: /connect/authorize and /connect/logout live on an
    // [ApiController] but are driven by a browser. Without this, an
    // unauthenticated authorization request 401s instead of redirecting to
    // sign-in, breaking the interactive OAuth flow for every client.
    //
    // Everything else defers to base, so the rest of the surface keeps whatever
    // the framework decides, now and in future releases.
    private static bool IsBrowserInteractiveEndpoint(HttpContext context) =>
        context.Request.Path.StartsWithSegments("/connect/authorize", StringComparison.OrdinalIgnoreCase) ||
        context.Request.Path.StartsWithSegments("/connect/logout", StringComparison.OrdinalIgnoreCase) ||
        context.Request.Path.StartsWithSegments("/connect/verify", StringComparison.OrdinalIgnoreCase);

    public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    {
        if (!IsBrowserInteractiveEndpoint(context.HttpContext))
        {
            return base.RedirectToLogin(context);
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    }

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        if (!IsBrowserInteractiveEndpoint(context.HttpContext))
        {
            return base.RedirectToAccessDenied(context);
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
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
