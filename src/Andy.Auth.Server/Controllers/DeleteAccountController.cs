using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Controllers;

[Authorize(AuthenticationSchemes = "Identity.Application")]
[AutoValidateAntiforgeryToken]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class DeleteAccountController(UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn, ApplicationDbContext db,
    AccountDeletionService deletion, ILogger<DeleteAccountController> logger) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await users.GetUserAsync(User);
        if (user == null) return Challenge();
        if (user.IsSystemUser) return Forbid();
        return View(new DeleteAccountViewModel
        {
            RequirePassword = await users.HasPasswordAsync(user),
            RequireSignIn = !await HasRecentSessionAsync(user.Id)
        });
    }

    [HttpPost]
    public async Task<IActionResult> Index(DeleteAccountViewModel model)
    {
        // Never accept a target user id, email, or password requirement from the form.
        var user = await users.GetUserAsync(User);
        if (user == null) return Challenge();
        if (user.IsSystemUser) return Forbid();
        model.RequirePassword = await users.HasPasswordAsync(user);
        model.RequireSignIn = !await HasRecentSessionAsync(user.Id);
        if (model.RequireSignIn) ModelState.AddModelError("", "Sign in again before deleting your account.");
        if (model.Confirmation != "DELETE") ModelState.AddModelError(nameof(model.Confirmation), "Type DELETE to confirm.");
        if (!ModelState.IsValid) return View(model);
        if (model.RequirePassword && (string.IsNullOrEmpty(model.Password) ||
            !(await signIn.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true)).Succeeded))
        {
            ModelState.AddModelError(nameof(model.Password), "Unable to confirm your password. Try again or sign in again.");
            return View(model);
        }
        try
        {
            await deletion.DeleteAsync(user);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Account deletion failed; transaction rolled back");
            ModelState.AddModelError("", "Your account could not be deleted. Please try again.");
            return View(model);
        }
        await signIn.SignOutAsync();
        TempData["SuccessMessage"] = "Your Andy Auth account has been deleted.";
        return RedirectToAction("Login", "Account");
    }

    [HttpPost]
    public async Task<IActionResult> SignInAgain()
    {
        await signIn.SignOutAsync();
        return RedirectToAction("Login", "Account", new { returnUrl = "/DeleteAccount" });
    }

    private Task<bool> HasRecentSessionAsync(string userId)
    {
        var sessionId = User.FindFirstValue(AndyAuthSignInManager.SessionIdClaimType);
        var now = DateTime.UtcNow;
        var oldest = now.AddMinutes(-5);
        // Cookie renewal and activity updates must not make an old sign-in fresh.
        return db.UserSessions.AnyAsync(s => s.UserId == userId && s.SessionId == sessionId &&
            !s.IsRevoked && s.ExpiresAt > now && s.CreatedAt >= oldest && s.CreatedAt <= now);
    }
}

public sealed class DeleteAccountViewModel
{
    public string? Password { get; set; }
    public string? Confirmation { get; set; }
    [BindNever] public bool RequirePassword { get; set; }
    [BindNever] public bool RequireSignIn { get; set; }
}
