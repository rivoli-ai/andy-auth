using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IdentityModel.Tokens.Jwt;

namespace Andy.Auth.Dpop;

public static class DpopBearerEvents
{
    public static JwtBearerEvents Create(JwtBearerEvents original, bool enabled, TimeSpan lifetime) => new()
    {
        OnAuthenticationFailed = original.AuthenticationFailed,
        OnForbidden = original.Forbidden,
        OnMessageReceived = async context =>
        {
            await original.MessageReceived(context);
            if (context.Result?.Failure != null) return;
            var header = context.Request.Headers.Authorization;
            if (!header.ToString().StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase)) return;
            if (!enabled || header.Count != 1)
            {
                DpopHttpProof.Reject(context.HttpContext, "invalid_token");
                context.Fail("DPoP is not enabled for this resource.");
                return;
            }
            var token = header.ToString()[5..].Trim();
            if (!await DpopHttpProof.VerifyAsync(context.HttpContext, token, lifetime))
                context.Fail("The DPoP proof could not be validated.");
            else context.Token = token;
        },
        OnTokenValidated = async context =>
        {
            await original.TokenValidated(context);
            if (context.Result?.Failure != null) return;
            var token = context.SecurityToken switch { JsonWebToken jwt => jwt.EncodedToken, JwtSecurityToken jwt => jwt.RawData, _ => "" };
            if (!DpopHttpProof.BindingSatisfied(context.HttpContext, context.Principal!, token))
            {
                DpopHttpProof.Reject(context.HttpContext, "invalid_token");
                context.Fail("Sender-constrained tokens require a matching proof of possession.");
            }
        },
        OnChallenge = async context =>
        {
            if (DpopHttpProof.HasFailure(context.HttpContext))
            {
                context.HandleResponse();
                DpopHttpProof.ApplyChallenge(context.HttpContext);
                return;
            }
            await original.Challenge(context);
        }
    };
}
