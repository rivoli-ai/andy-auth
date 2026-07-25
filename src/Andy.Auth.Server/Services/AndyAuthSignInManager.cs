using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;

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

    /// <summary>
    /// The claim type carrying the stable per-sign-in session identifier.
    /// </summary>
    public const string SessionIdClaimType = "session_id";

    /// <summary>
    /// Stamps a stable <c>session_id</c> onto the principal.
    /// </summary>
    /// <remarks>
    /// andy-auth#154. `SessionTrackingMiddleware`, `SessionController` and
    /// `SessionApiController` all read a `session_id` claim, but nothing ever
    /// issued one — so the middleware fell back to hashing the raw Identity
    /// cookie. Sliding expiration re-issues that cookie, the hash changed, and
    /// the middleware treated each renewal as a brand-new session: a fresh
    /// UserSessions row, and the concurrency limit evicting the user's older
    /// rows. Normal browsing manufactured and self-evicted sessions, and
    /// logout couldn't correlate the rows it was meant to close.
    /// <para>
    /// Minting it here means it is baked into the auth cookie at sign-in and
    /// survives every subsequent request. Re-issues of the principal —
    /// `RefreshSignInAsync` after a password change, the periodic
    /// security-stamp validation — carry the existing value forward from the
    /// current request rather than starting a new session.
    /// </para>
    /// </remarks>
    public override async Task<ClaimsPrincipal> CreateUserPrincipalAsync(ApplicationUser user)
    {
        var principal = await base.CreateUserPrincipalAsync(user);

        if (principal.Identity is ClaimsIdentity identity &&
            identity.FindFirst(SessionIdClaimType) is null)
        {
            identity.AddClaim(new Claim(
                SessionIdClaimType,
                CurrentSessionId() ?? Guid.NewGuid().ToString("N")));
        }

        return principal;
    }

    /// <summary>
    /// The session id on the in-flight request, if any. Accessed defensively:
    /// <see cref="SignInManager{TUser}.Context"/> throws when there is no
    /// HttpContext, which is the normal case in unit tests and in any
    /// background principal construction.
    /// </summary>
    private string? CurrentSessionId()
    {
        try
        {
            return Context?.User?.FindFirst(SessionIdClaimType)?.Value;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
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
