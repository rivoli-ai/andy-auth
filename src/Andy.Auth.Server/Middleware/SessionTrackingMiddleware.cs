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

        // Only track authenticated users
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var sessionId = GetSessionId(context);
            var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrEmpty(sessionId) && !string.IsNullOrEmpty(userId))
            {
                // One load instead of an existence probe followed by a second
                // read inside IsSessionValidAsync — this runs on every
                // non-skipped authenticated request (andy-auth#154).
                var session = await dbContext.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionId);

                if (session is null)
                {
                    // Auto-create session for authenticated user (first request after login)
                    var ipAddress = context.Connection.RemoteIpAddress?.ToString();
                    var userAgent = context.Request.Headers.UserAgent.FirstOrDefault();

                    try
                    {
                        await sessionService.CreateSessionAsync(userId, sessionId, ipAddress, userAgent);
                        _logger.LogInformation("Auto-created session {SessionId} for user {UserId}", sessionId, userId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to auto-create session {SessionId}", sessionId);
                    }
                }
                else
                {
                    // Validate session is still active, reusing the row we just
                    // loaded rather than reading it again.
                    var isValid = await sessionService.IsSessionValidAsync(session);

                    if (!isValid)
                    {
                        // Session has been revoked - sign out user
                        _logger.LogInformation("Session {SessionId} is no longer valid, signing out user", sessionId);

                        // Clear authentication cookie
                        await context.SignOutAsync(IdentityConstants.ApplicationScheme);

                        // Redirect to login if this is a web request
                        if (!IsApiRequest(context))
                        {
                            context.Response.Redirect("/Account/Login?sessionExpired=true");
                            return;
                        }
                        else
                        {
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                            return;
                        }
                    }

                    // Update session activity (throttled to avoid too many DB writes)
                    if (ShouldUpdateActivity(context, sessionId))
                    {
                        await sessionService.UpdateActivityAsync(sessionId);
                    }
                }
            }
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

    private static string? GetSessionId(HttpContext context)
    {
        // AndyAuthSignInManager stamps this at sign-in and carries it across
        // principal re-issues, so it is stable for the life of the session.
        //
        // The previous fallback — SHA-256 of the raw Identity cookie — changed
        // every time sliding expiration re-issued that cookie, so each renewal
        // looked like a brand-new session: another UserSessions row, and the
        // concurrency limit evicting the user's older rows (andy-auth#154).
        // There is no fallback now; a request with no claim is simply not
        // tracked, which is correct for bearer-token API calls.
        return context.User.FindFirst(Services.AndyAuthSignInManager.SessionIdClaimType)?.Value;
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
