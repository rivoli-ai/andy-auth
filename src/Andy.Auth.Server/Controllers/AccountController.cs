using System.Security.Claims;
using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Andy.Auth.Server.Controllers;

// This controller is mostly the pre-login surface (Login, Register,
// ExternalLogin, AccessDenied, 2FA prompts, recovery code, TestLogin), so it
// carries no class-level [Authorize]; actions that require a session declare
// their own.
//
// It previously claimed "the DefaultPolicy in Program.cs already requires
// authentication, so omitting the class-level attribute is enough". That was
// wrong (andy-auth#150): `AddAuthorization()` sets DefaultPolicy — consulted
// only to resolve an [Authorize] that names no policy — and leaves
// FallbackPolicy null, so an attribute-less action is anonymous. Anything
// added here that needs a session must say so explicitly; there is no
// implicit default protecting it.
public class AccountController : Controller
{
    /// <summary>
    /// The only failure message the login form ever shows. Distinguishing
    /// "no such account" / "disabled" / "wrong password" / "locked out" told an
    /// attacker which emails are real (andy-auth#50); the specific reason goes
    /// to the log and the audit trail instead.
    /// </summary>
    /// <remarks>
    /// This deliberately costs the locked-out user their explanation. Without a
    /// configured mail sender there is no side channel to deliver it, so the
    /// disclosure has to go rather than move. Revisit when email ships.
    /// </remarks>
    private const string GenericLoginFailureMessage =
        "Invalid login attempt. If the problem persists, contact your administrator.";

    /// <summary>
    /// A real PBKDF2 hash, verified against when the account doesn't exist so
    /// the response takes comparable time either way (andy-auth#50).
    /// </summary>
    private static readonly PasswordHasher<ApplicationUser> TimingEqualizer = new();

    private static readonly string DummyPasswordHash =
        TimingEqualizer.HashPassword(new ApplicationUser(), "andy-auth-timing-equalizer");

    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly SessionService _sessionService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        SessionService sessionService,
        IConfiguration configuration,
        ILogger<AccountController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _sessionService = sessionService;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        // If user is already authenticated, redirect them to the returnUrl (or home)
        if (User.Identity?.IsAuthenticated == true)
        {
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        ViewData["ReturnUrl"] = returnUrl;
        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        ViewData["ReturnUrl"] = model.ReturnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user == null)
        {
            // Burn the same PBKDF2 work a real verification would (andy-auth#50).
            // Returning early here made "no such account" answer in a fraction
            // of the time a wrong password took, which enumerates valid emails
            // just as reliably as a distinct error message does.
            // Uses its own hasher rather than _userManager.PasswordHasher so the
            // work happens identically regardless of how UserManager is wired.
            TimingEqualizer.VerifyHashedPassword(
                new ApplicationUser(), DummyPasswordHash, model.Password);

            _logger.LogWarning("Login refused: no account for {Email}", model.Email);
            await _auditService.LogAsync(
                "UserLoginFailed", null, model.Email, null, null,
                "No account for the supplied email", ipAddress);

            ModelState.AddModelError(string.Empty, GenericLoginFailureMessage);
            return View(model);
        }

        // Lifecycle gate (andy-auth#146). AndyAuthSignInManager enforces the
        // same predicate inside PasswordSignInAsync; checking first keeps the
        // disabled case out of the lockout counter. The specific reason is
        // logged and audited, never shown — "this account has been disabled"
        // confirms the account exists (andy-auth#50).
        var denialReason = UserLifecycle.GetDenialReason(user);
        if (denialReason is not null)
        {
            _logger.LogWarning(
                "Login refused for {Email}: {Reason}", user.Email, denialReason);
            await _auditService.LogAsync(
                "UserLoginFailed", user.Id, user.Email ?? model.Email, user.Id, user.Email,
                $"Login refused: {denialReason}", ipAddress);

            ModelState.AddModelError(string.Empty, GenericLoginFailureMessage);
            return View(model);
        }

        var result = await _signInManager.PasswordSignInAsync(
            user,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            // Check if user must change password on first login
            if (user.MustChangePassword)
            {
                _logger.LogInformation("User {Email} must change password on first login.", user.Email);
                return RedirectToAction(nameof(ChangePassword), new { returnUrl = model.ReturnUrl });
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log successful login
            await _auditService.LogAsync(
                "UserLogin",
                user.Id,
                user.Email ?? model.Email,
                user.Id,
                user.Email,
                "Successful login",
                ipAddress);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        if (result.RequiresTwoFactor)
        {
            return RedirectToAction("LoginWith2fa", new { model.ReturnUrl, model.RememberMe });
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User {Email} account locked out.", model.Email);

            // Log lockout
            await _auditService.LogAsync(
                "UserLockedOut",
                user.Id,
                user.Email ?? model.Email,
                user.Id,
                user.Email,
                "Account locked out due to failed login attempts",
                ipAddress);

            ModelState.AddModelError(string.Empty, GenericLoginFailureMessage);
            return View(model);
        }

        // Log failed login attempt
        await _auditService.LogAsync(
            "UserLoginFailed",
            user.Id,
            user.Email ?? model.Email,
            user.Id,
            user.Email,
            "Invalid password",
            ipAddress);

        ModelState.AddModelError(string.Empty, GenericLoginFailureMessage);
        return View(model);
    }

    [HttpGet]
    public IActionResult Register(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View(new RegisterViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        ViewData["ReturnUrl"] = model.ReturnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FullName = model.FullName,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} created a new account with password.", model.Email);

            // Log user registration
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _auditService.LogAsync(
                "UserRegistered",
                user.Id,
                user.Email ?? model.Email,
                user.Id,
                user.Email,
                "New user registration",
                ipAddress);

            // Sign in the user
            await _signInManager.SignInAsync(user, isPersistent: false);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        // Get current user before signing out
        var user = await _userManager.GetUserAsync(User);

        // Revoke all sessions for this user
        if (user != null)
        {
            try
            {
                var revokedCount = await _sessionService.RevokeAllSessionsAsync(user.Id, "User logged out");
                _logger.LogInformation("Revoked {Count} sessions for user {UserId} on logout", revokedCount, user.Id);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to revoke sessions on logout for user {UserId}", user.Id);
            }
        }

        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");

        // Log logout event
        if (user != null)
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _auditService.LogAsync(
                "UserLogout",
                user.Id,
                user.Email ?? "Unknown",
                user.Id,
                user.Email,
                "User logged out",
                ipAddress);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }

    /// <summary>
    /// Shows the two-factor authentication verification page.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> LoginWith2fa(string? returnUrl = null, bool rememberMe = false)
    {
        // Ensure the user has gone through the username & password screen first
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var model = new LoginWith2faViewModel
        {
            ReturnUrl = returnUrl,
            RememberMe = rememberMe
        };

        return View(model);
    }

    /// <summary>
    /// Verifies the two-factor authentication code.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
            authenticatorCode,
            model.RememberMe,
            model.RememberMachine);

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (result.Succeeded)
        {
            _logger.LogInformation("User {UserId} logged in with 2FA.", user.Id);

            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log 2FA login
            await _auditService.LogAsync(
                "UserLogin2FA",
                user.Id,
                user.Email ?? "Unknown",
                user.Id,
                user.Email,
                "Successful login with 2FA",
                ipAddress);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User {UserId} account locked out.", user.Id);

            // Log lockout
            await _auditService.LogAsync(
                "UserLockedOut",
                user.Id,
                user.Email ?? "Unknown",
                user.Id,
                user.Email,
                "Account locked out after failed 2FA attempts",
                ipAddress);

            ModelState.AddModelError(string.Empty, "This account has been locked out. Please try again later.");
            return View(model);
        }

        // Log failed 2FA attempt
        await _auditService.LogAsync(
            "UserLogin2FAFailed",
            user.Id,
            user.Email ?? "Unknown",
            user.Id,
            user.Email,
            "Invalid authenticator code",
            ipAddress);

        _logger.LogWarning("Invalid authenticator code entered for user {UserId}.", user.Id);
        ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
        return View(model);
    }

    /// <summary>
    /// Shows the recovery code login page.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> LoginWithRecoveryCode(string? returnUrl = null)
    {
        // Ensure the user has gone through the username & password screen first
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var model = new LoginWithRecoveryCodeViewModel
        {
            ReturnUrl = returnUrl
        };

        return View(model);
    }

    /// <summary>
    /// Verifies the recovery code and signs in the user.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

        var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (result.Succeeded)
        {
            _logger.LogInformation("User {UserId} logged in with a recovery code.", user.Id);

            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log recovery code login
            await _auditService.LogAsync(
                "UserLoginRecoveryCode",
                user.Id,
                user.Email ?? "Unknown",
                user.Id,
                user.Email,
                "Successful login with recovery code",
                ipAddress);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User {UserId} account locked out.", user.Id);

            // Log lockout
            await _auditService.LogAsync(
                "UserLockedOut",
                user.Id,
                user.Email ?? "Unknown",
                user.Id,
                user.Email,
                "Account locked out after failed recovery code attempts",
                ipAddress);

            ModelState.AddModelError(string.Empty, "This account has been locked out. Please try again later.");
            return View(model);
        }

        // Log failed recovery code attempt
        await _auditService.LogAsync(
            "UserLoginRecoveryCodeFailed",
            user.Id,
            user.Email ?? "Unknown",
            user.Id,
            user.Email,
            "Invalid recovery code",
            ipAddress);

        _logger.LogWarning("Invalid recovery code entered for user {UserId}.", user.Id);
        ModelState.AddModelError(string.Empty, "Invalid recovery code.");
        return View(model);
    }

    /// <summary>
    /// Gets the list of configured external authentication providers.
    /// </summary>
    public async Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync()
    {
        var schemes = await _signInManager.GetExternalAuthenticationSchemesAsync();
        return schemes;
    }

    /// <summary>
    /// Initiates an external login flow (e.g., Azure AD / Microsoft).
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider, string? returnUrl = null)
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    /// <summary>
    /// Handles the callback from external authentication providers.
    /// Creates or links user accounts as needed.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
    {
        returnUrl ??= Url.Content("~/");

        if (!string.IsNullOrEmpty(remoteError))
        {
            _logger.LogWarning("External login error: {Error}", remoteError);
            ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            _logger.LogWarning("External login info not available");
            ModelState.AddModelError(string.Empty, "Error loading external login information.");
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
        }

        // Try to sign in with the external login provider
        // Local 2FA is not bypassed (andy-auth#119). The upstream provider's
        // own MFA is its business; if this user enrolled a second factor *here*,
        // arriving via an external identity must not skip it.
        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: false);

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (signInResult.Succeeded)
        {
            _logger.LogInformation("User logged in with {Provider} provider.", info.LoginProvider);

            // Update last login time
            var existingUser = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (existingUser != null)
            {
                existingUser.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(existingUser);

                // Log external login
                await _auditService.LogAsync(
                    "UserLoginExternal",
                    existingUser.Id,
                    existingUser.Email ?? "Unknown",
                    existingUser.Id,
                    existingUser.Email,
                    $"Login via {info.LoginProvider}",
                    ipAddress);
            }

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        if (signInResult.RequiresTwoFactor)
        {
            return RedirectToAction(nameof(LoginWith2fa), new { returnUrl, rememberMe = false });
        }

        if (signInResult.IsLockedOut)
        {
            _logger.LogWarning("User account locked out.");
            ModelState.AddModelError(string.Empty, "This account has been locked out. Please try again later.");
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
        }

        // User doesn't have an account - create one or link to existing
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var name = info.Principal.FindFirstValue(ClaimTypes.Name)
                   ?? info.Principal.FindFirstValue("name")
                   ?? email;

        if (string.IsNullOrEmpty(email))
        {
            _logger.LogWarning("External login did not provide an email address");
            ModelState.AddModelError(string.Empty, "Email address is required from the external provider.");
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
        }

        // An email the provider hasn't verified proves nothing about who owns
        // it, and everything below keys off it (andy-auth#119). Providers that
        // don't emit the claim can be accepted per-deployment via
        // ExternalLogin:RequireVerifiedEmail=false, which is a deliberate
        // downgrade and should only be set for an IdP known to verify.
        var requireVerifiedEmail = _configuration.GetValue(
            "ExternalLogin:RequireVerifiedEmail", true);
        var emailVerified = string.Equals(
            info.Principal.FindFirstValue("email_verified"), "true", StringComparison.OrdinalIgnoreCase);

        if (requireVerifiedEmail && !emailVerified)
        {
            _logger.LogWarning(
                "External login refused: {Provider} did not assert a verified email for {Email}",
                info.LoginProvider, email);
            await _auditService.LogAsync(
                "ExternalLinkRejected", null, email, null, null,
                $"{info.LoginProvider} did not assert email_verified", ipAddress);

            ModelState.AddModelError(string.Empty,
                "Your identity provider did not confirm ownership of this email address.");
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
        }

        // Check if user already exists with this email
        var user = await _userManager.FindByEmailAsync(email);

        if (user != null)
        {
            // THE FIX (andy-auth#119). This used to attach the external identity
            // to the existing account and sign the caller straight in, on the
            // strength of a matching email alone. Against any provider that
            // lets an attacker assert someone else's address — or simply
            // doesn't verify — that is account takeover.
            //
            // Linking is now a separate, deliberate act performed *from* an
            // authenticated local session: see LinkExternalLogin below.
            _logger.LogWarning(
                "External login refused: {Email} already has a local account; linking must be " +
                "initiated from an authenticated session", email);
            await _auditService.LogAsync(
                "ExternalLinkRejected", user.Id, user.Email ?? email, user.Id, user.Email,
                $"Auto-link from {info.LoginProvider} refused; local account already exists", ipAddress);

            ModelState.AddModelError(string.Empty,
                "An account already exists for this email address. Sign in with your password first, " +
                "then link your external account from your profile.");
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
        }

        {
            // Create a new user account
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true, // Email is verified by external provider
                FullName = name ?? "",
                CreatedAt = DateTime.UtcNow,
                LastLoginAt = DateTime.UtcNow,
                IsActive = true
            };

            // Extract profile picture if available
            var picture = info.Principal.FindFirstValue("picture")
                          ?? info.Principal.FindFirstValue("urn:google:picture");
            if (!string.IsNullOrEmpty(picture))
            {
                user.ProfilePictureUrl = picture;
            }

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                foreach (var error in createResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
            }

            _logger.LogInformation("Created new user {Email} via {Provider} external login.", email, info.LoginProvider);

            // Log new user registration via external provider
            await _auditService.LogAsync(
                "UserRegisteredExternal",
                user.Id,
                user.Email ?? email,
                user.Id,
                user.Email,
                $"New user registered via {info.LoginProvider}",
                ipAddress);
        }

        // Attach the provider identity to the account we just created. This is
        // the only remaining auto-link, and it is safe because the account did
        // not exist a moment ago — there is no pre-existing owner to displace.
        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (!addLoginResult.Succeeded)
        {
            _logger.LogWarning("Failed to add external login for {Email}: {Errors}",
                email, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
        }

        // Sign in the user
        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("User {Email} signed in via {Provider}.", email, info.LoginProvider);

        await _auditService.LogAsync(
            "UserLoginExternal",
            user.Id,
            user.Email ?? email,
            user.Id,
            user.Email,
            $"Login via {info.LoginProvider}",
            ipAddress);

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }

    /// <summary>
    /// Starts linking an external identity to the <em>already signed-in</em>
    /// account.
    /// </summary>
    /// <remarks>
    /// andy-auth#119. <c>ExternalLoginCallback</c> no longer attaches a
    /// provider identity to an existing account just because the email
    /// matches, so this is the supported path: prove you hold the local
    /// account first, then attach. Requires a fresh password re-authentication
    /// so a borrowed browser session can't silently graft a permanent
    /// alternative credential onto the account.
    /// </remarks>
    [HttpPost]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LinkExternalLogin(string provider, string currentPassword)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToAction(nameof(Login));
        }

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        // Re-authenticate. An open session is not proof that the person at the
        // keyboard owns the account.
        if (!await _userManager.CheckPasswordAsync(user, currentPassword ?? string.Empty))
        {
            _logger.LogWarning(
                "External link refused for {UserId}: re-authentication failed", user.Id);
            await _auditService.LogAsync(
                "ExternalLinkRejected", user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Re-authentication failed while linking {provider}", ipAddress);

            TempData["ErrorMessage"] = "Password incorrect. External account not linked.";
            return RedirectToAction("Index", "Home");
        }

        await _auditService.LogAsync(
            "ExternalLinkRequested", user.Id, user.Email ?? "Unknown", user.Id, user.Email,
            $"Link to {provider} requested", ipAddress);

        var redirectUrl = Url.Action(nameof(LinkExternalLoginCallback), "Account");
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(
            provider, redirectUrl, _userManager.GetUserId(User));
        return Challenge(properties, provider);
    }

    /// <summary>
    /// Completes the link started by <see cref="LinkExternalLogin"/>, attaching
    /// the provider identity to the session that initiated it.
    /// </summary>
    [HttpGet]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    public async Task<IActionResult> LinkExternalLoginCallback()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToAction(nameof(Login));
        }

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var info = await _signInManager.GetExternalLoginInfoAsync(await _userManager.GetUserIdAsync(user));

        if (info is null)
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected", user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                "External login information was unavailable on callback", ipAddress);

            TempData["ErrorMessage"] = "Could not read the external login information.";
            return RedirectToAction("Index", "Home");
        }

        var result = await _userManager.AddLoginAsync(user, info);
        if (!result.Succeeded)
        {
            // Most often: this provider identity is already attached to a
            // different account. Refusing keeps one external identity bound to
            // one local account.
            _logger.LogWarning("Failed to link {Provider} for {UserId}: {Errors}",
                info.LoginProvider, user.Id,
                string.Join(", ", result.Errors.Select(e => e.Description)));
            await _auditService.LogAsync(
                "ExternalLinkRejected", user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Link to {info.LoginProvider} refused: {string.Join(", ", result.Errors.Select(e => e.Description))}",
                ipAddress);

            TempData["ErrorMessage"] = "That external account could not be linked.";
            return RedirectToAction("Index", "Home");
        }

        await _auditService.LogAsync(
            "ExternalLinkSucceeded", user.Id, user.Email ?? "Unknown", user.Id, user.Email,
            $"Linked to {info.LoginProvider}", ipAddress);

        // Drop the temporary external cookie the challenge left behind.
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        TempData["SuccessMessage"] = $"{info.LoginProvider} account linked.";
        return RedirectToAction("Index", "Home");
    }

    /// <summary>
    /// Test-only login endpoint that bypasses anti-forgery validation.
    /// Available in Development AND Embedded environments. Embedded
    /// is Conductor's standard environment string (see conductor#1162
    /// where the switch to `Embedded` was made so OpenIddict signing
    /// keys persist across launches). Without accepting Embedded
    /// here, `DevAutoSignIn` in Conductor gets a 404 and the user
    /// can't sign in to any Conductor feature.
    /// </summary>
    [HttpPost("~/Account/TestLogin")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> TestLogin([FromForm] string email, [FromForm] string password, [FromForm] string? returnUrl = null)
    {
        // Allow in any non-production environment (Development, Docker,
        // Embedded). Production deployments must use the real
        // sign-in flow; this endpoint is for local dev + Conductor's
        // embedded loopback only.
        var env = HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();
        if (!env.IsLocalOrEmbedded())
        {
            return NotFound();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || !UserLifecycle.CanAuthenticate(user))
        {
            return BadRequest(new { error = "Invalid credentials or inactive account" });
        }

        var result = await _signInManager.PasswordSignInAsync(
            user,
            password,
            isPersistent: false,
            lockoutOnFailure: false);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} logged in via test endpoint.", email);
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return Ok(new { success = true });
        }

        return BadRequest(new { error = "Invalid credentials" });
    }

    /// <summary>
    /// Shows the change password page. Required for users who must change their password on first login.
    /// </summary>
    [HttpGet]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    public IActionResult ChangePassword(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View(new ChangePasswordViewModel { ReturnUrl = returnUrl });
    }

    /// <summary>
    /// Processes the password change request.
    ///
    /// Closes andy-auth#45. Previously the controller called
    /// GeneratePasswordResetTokenAsync + ResetPasswordAsync, which let any
    /// authenticated session set a new password without proving knowledge of
    /// the existing one. Now we require <see cref="ChangePasswordViewModel.CurrentPassword"/>
    /// and use <see cref="UserManager{TUser}.ChangePasswordAsync"/>, which
    /// verifies the current password atomically. For users with 2FA enabled
    /// we also refresh the sign-in (rotates the auth cookie / security stamp);
    /// see TODO below for the full MFA re-challenge gap tracked under #45.
    /// </summary>
    [HttpPost]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        ViewData["ReturnUrl"] = model.ReturnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction(nameof(Login));
        }

        // Check if new password is the same as current password
        var isSamePassword = await _userManager.CheckPasswordAsync(user, model.NewPassword);
        if (isSamePassword)
        {
            ModelState.AddModelError(string.Empty, "New password cannot be the same as your current password.");
            return View(model);
        }

        // Validate password meets requirements
        var passwordValidator = new PasswordValidator<ApplicationUser>();
        var validationResult = await passwordValidator.ValidateAsync(_userManager, user, model.NewPassword);
        if (!validationResult.Succeeded)
        {
            foreach (var error in validationResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Verify the current password and change atomically. ChangePasswordAsync
        // returns IdentityResult with a "PasswordMismatch" error code when the
        // supplied current password is wrong; surface it generically so we
        // don't reveal whether the new password failed validation versus the
        // current one being wrong.
        var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // TODO(andy-auth#45): users with 2FA enabled should be sent through a
        // fresh MFA challenge before the change is finalised. The existing
        // LoginWith2fa flow stores TwoFactorAuthenticationUser via SignInManager
        // and is single-use after the password sign-in; reusing it here needs a
        // new "step-up" entry point. For now we refresh the sign-in cookie so
        // the security-stamp regeneration immediately invalidates any other
        // sessions. Tracked as a follow-up under the #45 issue.
        var twoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        if (twoFactorEnabled)
        {
            _logger.LogInformation(
                "User {Email} changed password with 2FA enabled; re-challenge is a known gap (andy-auth#45 follow-up).",
                user.Email);
        }
        await _signInManager.RefreshSignInAsync(user);

        // Clear the MustChangePassword flag and update last login time
        user.MustChangePassword = false;
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Log the password change
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _auditService.LogAsync(
            "UserPasswordChanged",
            user.Id,
            user.Email ?? "Unknown",
            user.Id,
            user.Email,
            "User changed their password",
            ipAddress);

        _logger.LogInformation("User {Email} changed their password.", user.Email);

        // Redirect to original destination or home
        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }

        return RedirectToAction("Index", "Home");
    }
}
