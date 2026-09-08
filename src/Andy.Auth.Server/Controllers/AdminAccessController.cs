using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Controllers;

[Authorize(Roles = "Admin", AuthenticationSchemes = "Identity.Application")]
[AutoValidateAntiforgeryToken]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class AdminAccessController(UserManager<ApplicationUser> users, SignInManager<ApplicationUser> signIn,
    ApplicationDbContext db) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(string? returnUrl = null)
    {
        var user = await users.GetUserAsync(User);
        if (user == null) return Challenge();
        return View(await PrepareAsync(user, new AdminAccessViewModel { ReturnUrl = SafeReturn(returnUrl) }));
    }

    [HttpPost]
    public async Task<IActionResult> Index(AdminAccessViewModel model)
    {
        var user = await users.GetUserAsync(User);
        if (user == null || !await users.IsInRoleAsync(user, "Admin")) return Forbid();
        await PrepareAsync(user, model);
        if (!model.MfaEnabled || model.RequireSignIn)
        {
            ModelState.AddModelError("", "Complete authenticator setup and sign in again before continuing.");
            return View(model);
        }
        var passwordOk = !model.RequirePassword || (!string.IsNullOrEmpty(model.Password) &&
            await users.CheckPasswordAsync(user, model.Password));
        var canSignIn = await signIn.CanSignInAsync(user) && !await users.IsLockedOutAsync(user);
        var code = (model.Code ?? "").Replace(" ", "").Replace("-", "");
        var codeOk = code.Length == 6 && await users.VerifyTwoFactorTokenAsync(user,
            users.Options.Tokens.AuthenticatorTokenProvider, code);
        if (!passwordOk || !codeOk || !canSignIn)
        {
            // Count the entire proof as one attempt. Checking the password through
            // SignInManager can reset failures for remembered-MFA clients before
            // the authenticator has been checked, defeating step-up lockout.
            if (canSignIn) await users.AccessFailedAsync(user);
            ModelState.AddModelError("", "We could not verify your password and authenticator code.");
            return View(model);
        }
        var sessionId = User.FindFirstValue(AndyAuthSignInManager.SessionIdClaimType);
        if (string.IsNullOrEmpty(sessionId)) return Forbid();
        await users.ResetAccessFailedCountAsync(user);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(AndyAuthSignInManager.SessionIdClaimType, sessionId),
            new Claim(AdminAccessFilter.StampClaim, await users.GetSecurityStampAsync(user))
        }, AdminAccessFilter.Scheme));
        await HttpContext.SignInAsync(AdminAccessFilter.Scheme, principal, new AuthenticationProperties
        {
            IsPersistent = false, AllowRefresh = false,
            ExpiresUtc = DateTimeOffset.UtcNow.Add(AdminAccessFilter.Lifetime)
        });
        return LocalRedirect(SafeReturn(model.ReturnUrl));
    }

    [HttpPost]
    public async Task<IActionResult> SignInAgain()
    {
        await HttpContext.SignOutAsync(AdminAccessFilter.Scheme);
        await signIn.SignOutAsync();
        return RedirectToAction("Login", "Account", new { returnUrl = "/AdminAccess" });
    }

    private async Task<AdminAccessViewModel> PrepareAsync(ApplicationUser user, AdminAccessViewModel model)
    {
        model.RequirePassword = await users.HasPasswordAsync(user);
        model.MfaEnabled = await users.GetTwoFactorEnabledAsync(user);
        model.ReturnUrl = SafeReturn(model.ReturnUrl);
        // Password accounts reauthenticate both factors here. External-only accounts
        // must pair the authenticator with a recent upstream sign-in session.
        var sessionId = User.FindFirstValue(AndyAuthSignInManager.SessionIdClaimType);
        var oldest = DateTime.UtcNow.Subtract(AdminAccessFilter.Lifetime);
        model.RequireSignIn = !model.RequirePassword && !await db.UserSessions.AnyAsync(s =>
            s.SessionId == sessionId && s.UserId == user.Id && !s.IsRevoked && s.CreatedAt >= oldest);
        return model;
    }

    private string SafeReturn(string? value)
    {
        if (value?.StartsWith('/') != true || !Url.IsLocalUrl(value)) return "/Admin";
        var path = new PathString(value!.Split('?')[0]);
        return path.StartsWithSegments("/Admin") || path.StartsWithSegments("/AdminServiceRoles") ? value : "/Admin";
    }
}

public sealed class AdminAccessViewModel
{
    public string? Password { get; set; }
    public string? Code { get; set; }
    public string? ReturnUrl { get; set; }
    [BindNever] public bool RequirePassword { get; set; }
    [BindNever] public bool MfaEnabled { get; set; }
    [BindNever] public bool RequireSignIn { get; set; }
}
