using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Andy.Auth.Server.Services;

/// <summary>Privileged bearer requests must reconcile authority on every request (#172).</summary>
public sealed class LiveAdminRequirement : IAuthorizationRequirement
{
    public const string Policy = "LiveAdmin";
}

public sealed class LiveAdminAuthorizationHandler(
    UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn,
    SessionService sessions,
    ApplicationDbContext db,
    ILogger<LiveAdminAuthorizationHandler> logger) : AuthorizationHandler<LiveAdminRequirement>
{
    internal const string Unavailable = "admin_session_truth_unavailable";

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, LiveAdminRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true || !context.User.IsInRole("Admin"))
            return;

        var subject = context.User.GetClaim(OpenIddictConstants.Claims.Subject);
        var sessionId = context.User.GetClaim(AndyAuthSignInManager.SessionIdClaimType);
        // Never substitute another session or interpret a missing session as M2M.
        // Client-credentials tokens carry no Admin role and use a separate profile.
        if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(sessionId))
            return;

        try
        {
            var tokenId = context.User.GetTokenId();
            // Bypass OpenIddict's process-local entity cache: a different replica
            // may have revoked the token or its authorization since our last read.
            var token = await db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
                .Where(entry => entry.Id == tokenId)
                .Select(entry => new { entry.Status, AuthorizationStatus = entry.Authorization == null
                    ? null : entry.Authorization.Status })
                .SingleOrDefaultAsync();
            if (token?.Status != OpenIddictConstants.Statuses.Valid ||
                token.AuthorizationStatus != OpenIddictConstants.Statuses.Valid)
                return;

            var user = await users.FindByIdAsync(subject);
            if (user is not null && await signIn.CanSignInAsync(user) &&
                !await users.IsLockedOutAsync(user) && await users.IsInRoleAsync(user, "Admin") &&
                await sessions.IsSessionValidForUserAsync(sessionId, subject))
                context.Succeed(requirement);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unable to reconcile privileged bearer session authority");
            context.Fail(new AuthorizationFailureReason(this, Unavailable));
        }
    }
}

/// <summary>A truth-store failure is transient, never permission to execute a privileged action.</summary>
public sealed class LiveAdminAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler fallback = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context,
        AuthorizationPolicy policy, PolicyAuthorizationResult result)
    {
        if (policy.Requirements.OfType<LiveAdminRequirement>().Any())
            context.Response.Headers.CacheControl = "no-store";

        if (result.AuthorizationFailure?.FailureReasons.Any(reason =>
                reason.Handler is LiveAdminAuthorizationHandler &&
                reason.Message == LiveAdminAuthorizationHandler.Unavailable) == true)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "5";
            await context.Response.WriteAsJsonAsync(new { error = "temporarily_unavailable" });
            return;
        }

        await fallback.HandleAsync(next, context, policy, result);
    }
}
