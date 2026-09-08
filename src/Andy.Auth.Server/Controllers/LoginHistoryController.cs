using System.Security.Claims;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Controllers;

[Authorize(AuthenticationSchemes = "Identity.Application")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class LoginHistoryController(ApplicationDbContext db) : Controller
{
    private static readonly string[] LoginActions =
    {
        "UserLogin", "UserLoginFailed", "UserLogin2FA", "UserLogin2FAFailed",
        "UserLoginRecoveryCode", "UserLoginRecoveryCodeFailed",
        "UserLoginExternal", "UserLoginExternalRejected"
    };

    [HttpGet]
    public async Task<IActionResult> Index(int? before = null)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId)) return Challenge();
        if (before is <= 0) return BadRequest();

        // Identity comes exclusively from the authenticated cookie. Never
        // accept an account/email selector or include general admin events.
        var query = db.AuditLogs.AsNoTracking().Where(entry =>
            entry.PerformedById == userId && LoginActions.Contains(entry.Action));
        if (before.HasValue) query = query.Where(entry => entry.Id < before.Value);
        var entries = await query.OrderByDescending(entry => entry.Id).Take(51)
            .Select(entry => new LoginHistoryEntry(entry.Id, entry.Action, entry.PerformedAt, entry.IpAddress))
            .ToListAsync(HttpContext.RequestAborted);
        var hasMore = entries.Count > 50;
        if (hasMore) entries.RemoveAt(50);
        return View(new LoginHistoryViewModel(entries, hasMore ? entries[^1].Id : null, before.HasValue));
    }
}

public sealed record LoginHistoryViewModel(IReadOnlyList<LoginHistoryEntry> Entries, int? NextCursor, bool IsOlderPage);
public sealed record LoginHistoryEntry(int Id, string Action, DateTime Timestamp, string? IpAddress)
{
    public bool Succeeded => Action is "UserLogin" or "UserLogin2FA" or "UserLoginRecoveryCode" or "UserLoginExternal";
    public string Method => Action switch
    {
        "UserLogin2FA" or "UserLogin2FAFailed" => "Two-factor",
        "UserLoginRecoveryCode" or "UserLoginRecoveryCodeFailed" => "Recovery code",
        "UserLoginExternal" or "UserLoginExternalRejected" => "External provider",
        _ => "Password"
    };
}
