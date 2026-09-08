using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Middleware;

/// <summary>
/// Middleware that tracks user session activity and validates sessions.
/// </summary>
public class SessionTrackingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SessionTrackingMiddleware> _logger;

    // Paths that never use the ASP.NET Identity application cookie. Do not
    // skip the entire /connect subtree: /connect/authorize, /connect/verify,
    // and /connect/logout are interactive browser endpoints and must enforce
    // per-session revocation before they issue or approve any artifact (#169).
    private static readonly string[] SkipPaths = new[]
    {
        "/css", "/js", "/images", "/favicon", "/.well-known", "/health", "/ready",
        "/connect/token", "/connect/introspect", "/connect/revoke",
        "/connect/userinfo", "/connect/device", "/connect/register"
    };

    public SessionTrackingMiddleware(RequestDelegate next, ILogger<SessionTrackingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, SessionService sessionService, ApplicationDbContext dbContext)
    {
        // Skip tracking for static files and health checks.
        // StartsWithSegments, not string.StartsWith: the raw prefix compare also
        // matched /healthz-internal, /connections, /jsonapi and anything else
        // sharing a prefix, silently dropping them from session tracking
        // (andy-auth#156).
        if (SkipPaths.Any(p => IsSkipped(context.Request.Path, p)))
        {
            await _next(context);
            return;
        }

        // Validate the application cookie specifically. Bearer identities do not
        // require an interactive session, even on non-/connect API routes.
        var cookie = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (cookie.Succeeded)
        {
            var sessionId = cookie.Principal?.FindFirst(AndyAuthSignInManager.SessionIdClaimType)?.Value;
            var userId = cookie.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var session = string.IsNullOrWhiteSpace(sessionId) ? null :
                await dbContext.UserSessions.FirstOrDefaultAsync(s => s.SessionId == sessionId);

            // SigningIn creates the record before issuing the cookie. Missing
            // records must fail closed; recreating one would undo revocation.
            if (session is null || string.IsNullOrWhiteSpace(userId) ||
                !string.Equals(session.UserId, userId, StringComparison.Ordinal) ||
                !await sessionService.IsSessionValidAsync(session))
            {
                _logger.LogInformation("Rejecting invalid backing session {SessionId}", sessionId);
                await context.SignOutAsync(IdentityConstants.ApplicationScheme);
                if (IsApiRequest(context))
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                else
                    context.Response.Redirect("/Account/Login?sessionExpired=true");
                return;
            }

            if (ShouldUpdateActivity(context, sessionId!))
                await sessionService.UpdateActivityAsync(sessionId!);
        }

        await _next(context);
    }

    /// <summary>
    /// True when <paramref name="path"/> falls under <paramref name="prefix"/>.
    /// </summary>
    /// <remarks>
    /// Segment-based, so `/healthz-internal` and `/connections` are no longer
    /// swept up by the `/health` and `/connect` entries the way a raw
    /// string.StartsWith did (andy-auth#156). The extra "prefix + dot" case
    /// keeps `/favicon.ico` matching `/favicon`: it is a single segment, so
    /// StartsWithSegments alone would miss it.
    /// </remarks>
    private static bool IsSkipped(PathString path, string prefix)
    {
        if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var value = path.Value;
        return value is not null
            && value.StartsWith(prefix + ".", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsApiRequest(HttpContext context)
    {
        var isInteractiveConnectEndpoint =
            context.Request.Path.StartsWithSegments("/connect/authorize") ||
            context.Request.Path.StartsWithSegments("/connect/verify") ||
            context.Request.Path.StartsWithSegments("/connect/logout");

        return context.Request.Headers.Accept.Any(h =>
            h?.Contains("application/json") == true) ||
            context.Request.Path.StartsWithSegments("/api") ||
            (context.Request.Path.StartsWithSegments("/connect") &&
             !isInteractiveConnectEndpoint);
    }

    private static bool ShouldUpdateActivity(HttpContext context, string sessionId)
    {
        // Only update activity every 5 minutes to reduce DB load.
        // Use IMemoryCache so throttling works across requests (HttpContext.Items is per-request).
        var cache = context.RequestServices.GetService<IMemoryCache>();
        if (cache == null)
        {
            // If cache isn't available for some reason, fall back to updating to preserve correctness.
            return true;
        }

        var key = $"session:last-activity:{sessionId}";
        if (cache.TryGetValue(key, out _))
        {
            return false;
        }

        cache.Set(key, true, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
        });

        return true;
    }
}

/// <summary>
/// Extension methods for adding session tracking middleware.
/// </summary>
public static class SessionTrackingMiddlewareExtensions
{
    public static IApplicationBuilder UseSessionTracking(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SessionTrackingMiddleware>();
    }
}
