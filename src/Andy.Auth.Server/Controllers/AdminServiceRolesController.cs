using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Controllers;

[AutoValidateAntiforgeryToken]
[Authorize(Roles = "Admin", AuthenticationSchemes = "Identity.Application")]
[ServiceFilter(typeof(AdminAccessFilter))]
public sealed class AdminServiceRolesController(
    UserManager<ApplicationUser> users,
    RoleManager<IdentityRole> roles,
    IAuditService audit,
    IUserAccessRevoker accessRevoker) : Controller
{
    public sealed record RolePage(string UserId, string Email, IReadOnlyList<string> Available, IList<string> Assigned);

    public async Task<IActionResult> Index(string userId)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null) return NotFound();
        var catalog = await roles.Roles.Select(r => r.Name!).OrderBy(n => n).ToListAsync();
        return View(new RolePage(user.Id, user.Email ?? user.UserName ?? user.Id,
            catalog.Where(n => !IsBuiltIn(n)).ToArray(), await users.GetRolesAsync(user)));
    }

    [HttpPost]
    public async Task<IActionResult> Create(string userId, string? role)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null) return NotFound();
        role = role?.Trim();
        if (string.IsNullOrWhiteSpace(role) || role.Length > 256 || role.Any(char.IsControl) || IsBuiltIn(role))
            return Error(userId, "Enter a service role name of 1–256 characters. Admin and User are managed separately.");
        var result = await roles.CreateAsync(new IdentityRole(role));
        if (!result.Succeeded) return Error(userId, string.Join(" ", result.Errors.Select(e => e.Description)));
        await Audit("ServiceRoleCreated", user, role);
        TempData["SuccessMessage"] = $"Service role '{role}' created. Select Grant to assign it.";
        return RedirectToAction(nameof(Index), new { userId });
    }

    [HttpPost]
    public async Task<IActionResult> Grant(string userId, string role) => await Change(userId, role, grant: true);

    [HttpPost]
    public async Task<IActionResult> Remove(string userId, string role) => await Change(userId, role, grant: false);

    private async Task<IActionResult> Change(string userId, string? role, bool grant)
    {
        if (string.IsNullOrWhiteSpace(role) || IsBuiltIn(role))
            return Error(userId, "Use the user administration controls to change Admin or User membership.");
        var user = await users.FindByIdAsync(userId);
        if (user is null) return NotFound();
        var existingRole = await roles.FindByNameAsync(role);
        if (existingRole?.Name is not string name) return Error(userId, "Service role not found.");
        if (IsBuiltIn(name)) return Error(userId, "Built-in roles cannot be changed here.");
        if (await users.IsInRoleAsync(user, name) == grant)
            return RedirectToAction(nameof(Index), new { userId });
        var result = grant ? await users.AddToRoleAsync(user, name) : await users.RemoveFromRoleAsync(user, name);
        if (!result.Succeeded) return Error(userId, string.Join(" ", result.Errors.Select(e => e.Description)));
        await Audit(grant ? "ServiceRoleGranted" : "ServiceRoleRemoved", user, name);
        await accessRevoker.RevokeAllAccessAsync(user, "Service role membership changed");
        TempData["SuccessMessage"] = $"Service role '{name}' {(grant ? "granted" : "removed")}. The user must sign in again to receive updated claims.";
        return RedirectToAction(nameof(Index), new { userId });
    }

    internal static bool IsBuiltIn(string name) =>
        name.Equals("Admin", StringComparison.OrdinalIgnoreCase) || name.Equals("User", StringComparison.OrdinalIgnoreCase);

    private IActionResult Error(string userId, string message)
    {
        TempData["ErrorMessage"] = message;
        return RedirectToAction(nameof(Index), new { userId });
    }

    private Task Audit(string action, ApplicationUser user, string role) => audit.LogAsync(action,
        User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown",
        User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue("email") ?? "unknown",
        user.Id, user.Email, $"Service role: {role}", HttpContext.Connection.RemoteIpAddress?.ToString());
}
