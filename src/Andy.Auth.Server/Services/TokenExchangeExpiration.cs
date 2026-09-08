using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Andy.Auth.Server.Services;

/// <summary>Caps the final token after OpenIddict computes its issuance dates.</summary>
public static class TokenExchangeExpiration
{
    public static ValueTask ApplyAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        if (context.Request.GrantType != TokenExchangeConstants.GrantType ||
            context.IssuedTokenPrincipal is null)
            return ValueTask.CompletedTask;

        var ceiling = context.Principal.GetExpirationDate();
        if (ceiling is null || ceiling <= context.Options.TimeProvider.GetUtcNow())
        {
            context.Reject(OpenIddictConstants.Errors.InvalidGrant,
                "subject_token has no usable remaining lifetime.");
            return ValueTask.CompletedTask;
        }

        var expiration = context.IssuedTokenPrincipal.GetExpirationDate();
        if (expiration is null || expiration > ceiling)
            context.IssuedTokenPrincipal.SetExpirationDate(ceiling);
        return ValueTask.CompletedTask;
    }
}
