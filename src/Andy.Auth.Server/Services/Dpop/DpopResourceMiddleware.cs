using Andy.Auth.Dpop;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Services.Dpop;

public sealed class DpopResourceMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, IOptions<DpopOptions> options)
    {
        context.Response.OnStarting(() => { DpopHttpProof.ApplyChallenge(context); return Task.CompletedTask; });
        var header = context.Request.Headers.Authorization;
        if (header.ToString().StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            if (!options.Value.Enabled || header.Count != 1)
            {
                DpopHttpProof.Reject(context, "invalid_token");
                DpopHttpProof.ApplyChallenge(context);
                return;
            }
            var token = header.ToString()[5..].Trim();
            if (!await DpopHttpProof.VerifyAsync(context, token, options.Value.ProofLifetime))
            {
                DpopHttpProof.ApplyChallenge(context);
                return;
            }
            // Native OpenIddict handlers understand Bearer. The verified proof
            // remains request-bound and is checked again against the validated
            // token's cnf by both server and validation event handlers.
            context.Request.Headers.Authorization = "Bearer " + token;
        }
        await next(context);
    }
}
