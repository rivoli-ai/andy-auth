using System.Security.Claims;
using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Andy.Auth.Server.Services;

/// <summary>Additional short-lived proof for interactive administration; never an authentication replacement.</summary>
public sealed class AdminAccessFilter(IHostEnvironment environment, IConfiguration configuration,
    UserManager<ApplicationUser> users) : IAsyncActionFilter
{
    public const string Scheme = "Andy.AdminAccess";
    public const string StampClaim = "admin_security_stamp";
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (environment.IsLocalOrEmbedded() && !configuration.GetValue<bool>("AdminAccess:EnforceInLocal"))
        {
            await next();
            return;
        }
        var http = context.HttpContext;
        var user = await users.GetUserAsync(http.User);
        if (user == null || !await users.IsInRoleAsync(user, "Admin"))
        {
            context.Result = new ForbidResult(IdentityConstants.ApplicationScheme);
            return;
        }
        var proof = await http.AuthenticateAsync(Scheme);
        var sessionId = http.User.FindFirstValue(AndyAuthSignInManager.SessionIdClaimType);
        if (proof.Succeeded && !string.IsNullOrEmpty(sessionId) &&
            proof.Principal?.FindFirstValue(ClaimTypes.NameIdentifier) == user.Id &&
            proof.Principal.FindFirstValue(AndyAuthSignInManager.SessionIdClaimType) == sessionId &&
            proof.Principal.FindFirstValue(StampClaim) == await users.GetSecurityStampAsync(user) &&
            await users.GetTwoFactorEnabledAsync(user))
        {
            await next();
            return;
        }
        context.Result = new RedirectToActionResult("Index", "AdminAccess", new
        {
            returnUrl = HttpMethods.IsGet(http.Request.Method)
                ? http.Request.Path + http.Request.QueryString : "/Admin"
        });
    }
}
