using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Revocation;

public static class RevocationBearerEvents
{
    private static readonly object Unavailable = new();
    public static JwtBearerEvents Create(JwtBearerEvents original) => new()
    {
        OnMessageReceived = original.MessageReceived,
        OnAuthenticationFailed = original.AuthenticationFailed,
        OnForbidden = original.Forbidden,
        OnTokenValidated = async context =>
        {
            await original.TokenValidated(context);
            if (context.Result?.Failure != null) return;
            var session = context.Principal?.FindFirst("session_id")?.Value;
            if (string.IsNullOrEmpty(session))
            {
                context.Fail("A user-bound session is required by this notification profile.");
                return;
            }
            try
            {
                if (await context.HttpContext.RequestServices.GetRequiredService<IRevokedSessionStore>()
                    .IsRevokedAsync(context.SecurityToken.Issuer, session, context.HttpContext.RequestAborted))
                    context.Fail("The session has been revoked.");
            }
            catch (Exception)
            {
                context.HttpContext.Items[Unavailable] = true;
                context.Fail("Revocation state is temporarily unavailable.");
            }
        },
        OnChallenge = async context =>
        {
            if (context.HttpContext.Items.ContainsKey(Unavailable))
            {
                context.HandleResponse();
                context.Response.StatusCode = 503;
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers.RetryAfter = "5";
                return;
            }
            await original.Challenge(context);
        }
    };
}
