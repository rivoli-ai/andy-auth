using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace Andy.Auth.Server.Services;

/// <summary>Session truth must include fresh token/grant authority across replicas.</summary>
public sealed class LiveSessionTokenFilter(ApplicationDbContext db, ILogger<LiveSessionTokenFilter> logger) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        context.HttpContext.Response.Headers.CacheControl = "no-store";
        try
        {
            var id = context.HttpContext.User.GetTokenId();
            var token = await db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
                .Where(entry => entry.Id == id)
                .Select(entry => new { entry.Status, AuthorizationStatus = entry.Authorization == null ? null : entry.Authorization.Status })
                .SingleOrDefaultAsync(context.HttpContext.RequestAborted);
            if (token?.Status != OpenIddictConstants.Statuses.Valid ||
                token.AuthorizationStatus != OpenIddictConstants.Statuses.Valid)
            {
                context.Result = new UnauthorizedObjectResult(new { reason = "invalid_token" });
                return;
            }
        }
        catch (Exception error)
        {
            logger.LogError(error, "Unable to reconcile session-truth token authority");
            context.HttpContext.Response.Headers.RetryAfter = "5";
            context.Result = new ObjectResult(new { reason = "temporarily_unavailable" }) { StatusCode = 503 };
            return;
        }
        await next();
    }
}
