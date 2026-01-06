using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
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

    // Paths to skip session tracking
    private static readonly string[] SkipPaths = new[]
    {
        "/css", "/js", "/images", "/favicon", "/.well-known", "/health", "/connect"
    };

    public SessionTrackingMiddleware(RequestDelegate next, ILogger<SessionTrackingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, SessionService sessionService, ApplicationDbContext dbContext)
    {
        // Skip tracking for static files and health checks
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
        if (SkipPaths.Any(p => path.StartsWith(p)))
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
                // Check if session exists in database
                var sessionExists = await dbContext.UserSessions
                    .AnyAsync(s => s.SessionId == sessionId);

                if (!sessionExists)
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
                    // Validate session is still active
                    var isValid = await sessionService.IsSessionValidAsync(sessionId);

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
                    if (ShouldUpdateActivity(context))
                    {
                        await sessionService.UpdateActivityAsync(sessionId);
                    }
                }
            }
        }

        await _next(context);
    }

    private static string? GetSessionId(HttpContext context)
    {
        // Get session ID from claims or cookie
        var sessionClaim = context.User.FindFirst("session_id");
        if (sessionClaim != null)
        {
            return sessionClaim.Value;
        }

        // Fallback: use authentication ticket ID
        if (context.Request.Cookies.TryGetValue(".AspNetCore.Identity.Application", out var cookie))
        {
            // Use a hash of the cookie as session ID
            return Convert.ToBase64String(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(cookie)
                )
            )[..32];
        }

        return null;
    }

    private static bool IsApiRequest(HttpContext context)
    {
        return context.Request.Headers.Accept.Any(h =>
            h?.Contains("application/json") == true) ||
            context.Request.Path.StartsWithSegments("/api") ||
            context.Request.Path.StartsWithSegments("/connect");
    }

    private static bool ShouldUpdateActivity(HttpContext context)
    {
        // Only update activity every 5 minutes to reduce DB load
        // Check if we have a marker in items
        const string LastActivityKey = "SessionLastActivityUpdate";

        if (context.Items.ContainsKey(LastActivityKey))
            return false;

        context.Items[LastActivityKey] = DateTime.UtcNow;
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
