using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Andy.Auth.Server.Controllers;

[AllowAnonymous]
public class AccountController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly SessionService _sessionService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        SessionService sessionService,
        ILogger<AccountController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _sessionService = sessionService;
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

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        if (!user.IsActive)
        {
            ModelState.AddModelError(string.Empty, "This account has been disabled.");
            return View(model);
        }

        var result = await _signInManager.PasswordSignInAsync(
            user,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true);

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

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

            ModelState.AddModelError(string.Empty, "This account has been locked out. Please try again later.");
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

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
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
        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

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

        // Check if user already exists with this email
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
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
        else
        {
            // User exists - check if account is active
            if (!user.IsActive)
            {
                ModelState.AddModelError(string.Empty, "This account has been disabled.");
                return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Linked {Provider} login to existing user {Email}.", info.LoginProvider, email);
        }

        // Link the external login to the user account
        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (!addLoginResult.Succeeded)
        {
            // Login might already be linked (e.g., if user registered with same email)
            _logger.LogWarning("Failed to add external login for {Email}: {Errors}",
                email, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
        }

        // Sign in the user
        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("User {Email} signed in via {Provider}.", email, info.LoginProvider);

        // Log external login (for existing user linking)
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
    /// Test-only login endpoint that bypasses anti-forgery validation.
    /// Only available in Development environment.
    /// </summary>
    [HttpPost("~/Account/TestLogin")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> TestLogin([FromForm] string email, [FromForm] string password, [FromForm] string? returnUrl = null)
    {
        // Only allow in development environment
        var env = HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();
        if (!env.IsDevelopment())
        {
            return NotFound();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || !user.IsActive)
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

        // Generate token and reset password
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Clear the MustChangePassword flag and update last login time
        user.MustChangePassword = false;
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Update security stamp to invalidate existing tokens
        await _userManager.UpdateSecurityStampAsync(user);

        // Log the password change
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _auditService.LogAsync(
            "UserPasswordChanged",
            user.Id,
            user.Email ?? "Unknown",
            user.Id,
            user.Email,
            "User changed their password (first login requirement)",
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
