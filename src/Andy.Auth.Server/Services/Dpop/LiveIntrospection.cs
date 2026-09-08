using System.Text.Json;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Andy.Auth.Server.Services.Dpop;

/// <summary>Fresh authority after native introspection client and authorized-party checks.</summary>
public sealed class LiveIntrospection(ApplicationDbContext db, UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn, SessionService sessions, ILogger<LiveIntrospection> logger)
    : IOpenIddictServerHandler<HandleIntrospectionRequestContext>
{
    public async ValueTask HandleAsync(HandleIntrospectionRequestContext context)
    {
        var principal = context.GenericTokenPrincipal;
        if (principal == null) return;
        var http = context.Transaction.GetHttpRequest()!.HttpContext;
        http.Response.Headers.CacheControl = "no-store";
        try
        {
            var id = principal.GetTokenId();
            var token = await db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
                .Where(row => row.Id == id).Select(row => new
                {
                    row.Status, HasAuthorization = row.Authorization != null,
                    GrantStatus = row.Authorization == null ? null : row.Authorization.Status
                }).SingleOrDefaultAsync(http.RequestAborted);
            if (token?.Status != OpenIddictConstants.Statuses.Valid ||
                token.HasAuthorization && token.GrantStatus != OpenIddictConstants.Statuses.Valid)
            { context.Reject(OpenIddictConstants.Errors.InvalidToken); return; }
            var session = principal.GetClaim("session_id");
            // Machine credentials have no user session. User grants must retain one.
            if (session == null && !token.HasAuthorization) return;
            var subject = principal.GetClaim(OpenIddictConstants.Claims.Subject);
            var user = subject == null ? null : await users.FindByIdAsync(subject);
            if (user == null || user.DeletedAt != null || !await signIn.CanSignInAsync(user) ||
                await users.IsLockedOutAsync(user) || !await sessions.IsSessionValidForUserAsync(session, user.Id))
            { context.Reject(OpenIddictConstants.Errors.InvalidToken); return; }
            context.Claims["session_id"] = session;
            context.Claims["roles"] = JsonSerializer.SerializeToElement((await users.GetRolesAsync(user))
                .Where(role => principal.GetClaims(OpenIddictConstants.Claims.Role).Contains(role)).ToArray());
        }
        catch (Exception error)
        {
            logger.LogError(error, "Introspection authority unavailable");
            http.Response.StatusCode = 503;
            http.Response.Headers.RetryAfter = "5";
            await http.Response.WriteAsJsonAsync(new { error = "temporarily_unavailable" }, http.RequestAborted);
            context.HandleRequest();
        }
    }
}
