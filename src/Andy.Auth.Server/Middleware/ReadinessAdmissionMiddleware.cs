using Andy.Auth.Server.Configuration;

namespace Andy.Auth.Server.Middleware;

public sealed class ReadinessAdmissionMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, StartupReadinessState state)
    {
        if (!state.IsReady && context.Request.Path != "/health" && context.Request.Path != "/ready")
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.RetryAfter = "5";
            await context.Response.WriteAsync("Service initialization is incomplete.");
            return;
        }
        await next(context);
    }
}
