using System.Security.Claims;
using System.Text.Json;
using Andy.Auth.Dpop;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Andy.Auth.Server.Services.Dpop;

public static class DpopBinding
{
    public const string Key = "andy.dpop.key";
    public const string BoundKey = "andy.dpop.bound";
    public const string Checked = "andy.dpop.checked";
    public const string PrivateClaim = "oi_andy_dpop_jkt";
    public const string Requirement = "ft:andy_dpop";
}

public sealed class ValidateTokenProof(IOptions<DpopOptions> options, IServiceProvider services,
    DpopNonceService nonces, IOpenIddictApplicationManager applications) : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token || context.Transaction.GetProperty<string>(DpopBinding.Checked) != null) return;
        context.Transaction.SetProperty(DpopBinding.Checked, "true");
        var request = context.Transaction.GetHttpRequest()!;
        var header = request.Headers["DPoP"];
        var application = !string.IsNullOrEmpty(context.Request?.ClientId)
            ? await applications.FindByClientIdAsync(context.Request.ClientId, context.CancellationToken) : null;
        var required = application != null && await applications.HasRequirementAsync(application, DpopBinding.Requirement, context.CancellationToken);
        if (header.Count == 0)
        {
            if (required) context.Reject("invalid_dpop_proof", "This client requires a proof of possession.");
            return;
        }
        if (!options.Value.Enabled || header.Count != 1 || !request.IsHttps)
        {
            context.Reject("invalid_dpop_proof", "The proof of possession could not be accepted.");
            return;
        }
        try
        {
            var result = await services.GetRequiredService<DpopProofValidator>().ValidateAsync(header[0]!, request.Method, new Uri(request.GetEncodedUrl()), options.Value.ProofLifetime,
                nonceValidator: options.Value.RequireNonce ? nonces.Validate : null, cancellationToken: context.CancellationToken);
            if (!result.Succeeded)
            {
                if (result.Error == "use_dpop_nonce") request.HttpContext.Response.Headers["DPoP-Nonce"] = nonces.Create(result.Thumbprint!, options.Value.ProofLifetime);
                context.Reject(result.Error ?? "invalid_dpop_proof", "A fresh valid proof of possession is required.");
                return;
            }
            context.Transaction.SetProperty(DpopBinding.Key, result.Thumbprint);
        }
        catch (Exception)
        {
            request.HttpContext.Response.StatusCode = 503;
            request.HttpContext.Response.Headers.RetryAfter = "5";
            request.HttpContext.Response.Headers.CacheControl = "no-store";
            await request.HttpContext.Response.WriteAsJsonAsync(new { error = "temporarily_unavailable" }, context.CancellationToken);
            context.HandleRequest();
        }
    }
}

public sealed class CaptureArtifactBinding : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        if (context.EndpointType == OpenIddictServerEndpointType.Token)
        {
            var artifact = context.AuthorizationCodePrincipal ?? context.RefreshTokenPrincipal ?? context.DeviceCodePrincipal;
            var key = artifact?.GetClaim(DpopBinding.PrivateClaim);
            if (key != null)
            {
                context.Transaction.SetProperty(DpopBinding.BoundKey, key);
                if (key != context.Transaction.GetProperty<string>(DpopBinding.Key))
                    context.Reject("invalid_dpop_proof", "The proof must use the key bound to this grant.");
            }
        }
        if (context.EndpointType == OpenIddictServerEndpointType.UserInfo && context.AccessTokenPrincipal != null &&
            !DpopHttpProof.BindingSatisfied(context.Transaction.GetHttpRequest()!.HttpContext, context.AccessTokenPrincipal, context.AccessToken!))
        {
            DpopHttpProof.Reject(context.Transaction.GetHttpRequest()!.HttpContext, "invalid_token");
            context.Reject(OpenIddictConstants.Errors.InvalidToken, "A matching proof of possession is required.");
        }
        return ValueTask.CompletedTask;
    }
}

public sealed class AttachProofBinding : IOpenIddictServerHandler<ProcessSignInContext>
{
    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        if (context.EndpointType == OpenIddictServerEndpointType.Authorization)
        {
            var key = (string?)context.Request?["dpop_jkt"];
            if (!string.IsNullOrEmpty(key)) context.Principal!.SetClaim(DpopBinding.PrivateClaim, key);
        }
        else if (context.EndpointType == OpenIddictServerEndpointType.Token)
        {
            var key = context.Transaction.GetProperty<string>(DpopBinding.Key);
            var bound = context.Transaction.GetProperty<string>(DpopBinding.BoundKey);
            if (bound != null && bound != key)
            {
                context.Reject("invalid_dpop_proof", "The proof must use the key bound to this grant.");
                return ValueTask.CompletedTask;
            }
            if (key != null)
            {
                context.Principal!.SetClaim(DpopBinding.PrivateClaim, key);
                context.Principal.SetClaim("cnf", JsonSerializer.SerializeToElement(new Dictionary<string, string> { ["jkt"] = key }));
                context.Principal.SetDestinations(claim => claim.Type == "cnf" ?
                    new[] { OpenIddictConstants.Destinations.AccessToken } : claim.GetDestinations());
            }
        }
        return ValueTask.CompletedTask;
    }
}
