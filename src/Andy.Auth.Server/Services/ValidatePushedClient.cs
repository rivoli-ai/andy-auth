using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Andy.Auth.Server.Services;

/// <summary>DCR administrative approval applies before PAR state is created as well as at redemption.</summary>
public sealed class ValidatePushedClient(DcrClientGate clients) :
    IOpenIddictServerHandler<OpenIddictServerEvents.ValidatePushedAuthorizationRequestContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidatePushedAuthorizationRequestContext context)
    {
        if (string.IsNullOrEmpty(context.ClientId)) return;
        var denial = await clients.GetDenialReasonAsync(context.ClientId);
        if (denial is not null)
            context.Reject(OpenIddictConstants.Errors.InvalidClient, denial);
    }
}
