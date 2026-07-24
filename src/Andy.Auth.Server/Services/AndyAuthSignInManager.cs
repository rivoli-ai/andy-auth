using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Services;

/// <summary>
/// <see cref="SignInManager{TUser}"/> that additionally enforces the account
/// lifecycle flags in <see cref="UserLifecycle"/>.
/// </summary>
/// <remarks>
/// <para>
/// andy-auth#146. Stock <c>CanSignInAsync</c> checks only the configured
/// confirmed-email / confirmed-phone requirements, so
/// <c>AuthorizationController</c>'s "is the user still allowed to sign in?"
/// gate on the authorization_code / refresh_token / device_code path was
/// passing suspended, expired, and soft-deleted accounts. Overriding here
/// fixes every consumer at once — interactive login (<c>PreSignInCheck</c>
/// runs on the password path), external login, the OpenIddict grants, and
/// <c>SessionApiController</c> — rather than bolting a different subset of
/// the rules onto each call site.
/// </para>
/// <para>
/// The denial reason is logged, never returned: telling an unauthenticated
/// caller "suspended" rather than "invalid login" is the enumeration oracle
/// tracked in andy-auth#50.
/// </para>
/// </remarks>
public class AndyAuthSignInManager : SignInManager<ApplicationUser>
{
    public AndyAuthSignInManager(
        UserManager<ApplicationUser> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<ApplicationUser>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<ApplicationUser> confirmation)
        : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
    }

    public override async Task<bool> CanSignInAsync(ApplicationUser user)
    {
        var denial = UserLifecycle.GetDenialReason(user);
        if (denial is not null)
        {
            Logger.LogWarning(
                "Sign-in refused for user {UserId}: {Reason}", user.Id, denial);
            return false;
        }

        return await base.CanSignInAsync(user);
    }
}
