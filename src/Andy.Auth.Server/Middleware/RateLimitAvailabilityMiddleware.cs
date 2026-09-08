using StackExchange.Redis;

namespace Andy.Auth.Server.Middleware;

/// <summary>Never fall back to per-process allowances when the shared counter is unavailable.</summary>
public sealed class RateLimitAvailabilityMiddleware(RequestDelegate next, ILogger<RateLimitAvailabilityMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try { await next(context); }
        catch (RedisException) when (!context.Response.HasStarted)
        {
            logger.LogWarning("Shared rate-limit store unavailable; rejecting request");
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.RetryAfter = "5";
        }
    }
}
