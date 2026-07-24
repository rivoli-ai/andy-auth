using Andy.Auth.Server.Data;

namespace Andy.Auth.Server.Services;

/// <summary>
/// The single predicate deciding whether an account is permitted to
/// authenticate. andy-auth#146: <see cref="ApplicationUser.IsSuspended"/>,
/// <see cref="ApplicationUser.ExpiresAt"/> and
/// <see cref="ApplicationUser.DeletedAt"/> were written by the admin surfaces
/// but read by no authentication path, so suspending or expiring a user did
/// nothing and a refresh token outlived a soft delete. Every path that mints
/// or renews credentials now funnels through here rather than re-deriving its
/// own subset of the rules.
/// </summary>
/// <remarks>
/// Enforced centrally by <see cref="AndyAuthSignInManager.CanSignInAsync"/>,
/// which ASP.NET Core Identity consults from <c>PreSignInCheck</c> — that
/// covers interactive password sign-in, external login, and every
/// OpenIddict grant that already called <c>CanSignInAsync</c>. Call sites
/// that need to reject *before* reaching Identity (or that report their own
/// error shape, such as the RFC 8693 token exchange) use
/// <see cref="GetDenialReason"/> directly.
/// </remarks>
public static class UserLifecycle
{
    /// <summary>
    /// Returns null when the account may authenticate, otherwise a short
    /// reason suitable for logs and audit records.
    /// </summary>
    /// <remarks>
    /// The reason is deliberately NOT safe to return to an unauthenticated
    /// caller verbatim — distinguishing "suspended" from "no such user" is
    /// the enumeration oracle tracked in andy-auth#50. Callers surface a
    /// generic message and log the specific one.
    /// </remarks>
    public static string? GetDenialReason(ApplicationUser user, DateTime utcNow)
    {
        if (user.DeletedAt is not null)
        {
            return "account is deleted";
        }

        if (!user.IsActive)
        {
            return "account is inactive";
        }

        if (user.IsSuspended)
        {
            return "account is suspended";
        }

        if (user.ExpiresAt is { } expiresAt && expiresAt <= utcNow)
        {
            return "account expired";
        }

        return null;
    }

    /// <inheritdoc cref="GetDenialReason(ApplicationUser, DateTime)"/>
    public static string? GetDenialReason(ApplicationUser user) =>
        GetDenialReason(user, DateTime.UtcNow);

    /// <summary>True when the account is permitted to authenticate.</summary>
    public static bool CanAuthenticate(ApplicationUser user) =>
        GetDenialReason(user) is null;
}
