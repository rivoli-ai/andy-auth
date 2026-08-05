using System.Net;
using System.Security.Claims;
using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

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
    /// The only failure message the login form shows to a caller who has not
    /// supplied the correct password. Distinguishing "no such account" /
    /// "disabled" / "wrong password" / "locked out" told an attacker which
    /// addresses are real (andy-auth#50).
    /// </summary>
    private const string GenericLoginFailureMessage =
        "Invalid login attempt. If the problem persists, contact your administrator.";

    /// <summary>Shown only once the correct password has been supplied.</summary>
    private const string LockedOutMessage =
        "This account is temporarily locked after too many failed sign-in attempts. " +
        "Try again in 30 minutes, or contact your administrator.";

    /// <summary>Shown only once the correct password has been supplied.</summary>
    private const string AccountDisabledMessage =
        "This account is not currently able to sign in. Contact your administrator.";

    private static readonly PasswordHasher<ApplicationUser> TimingEqualizer = new();

    /// <summary>
    /// A real PBKDF2 hash, verified against when the account doesn't exist so
    /// the response takes comparable time either way (andy-auth#50).
    /// </summary>
    private static readonly string DummyPasswordHash =
        TimingEqualizer.HashPassword(new ApplicationUser(), "andy-auth-timing-equalizer");

    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly IUserAccessRevoker _accessRevoker;
    private readonly ExternalLoginOptions _externalLoginOptions;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        IUserAccessRevoker accessRevoker,
        IOptions<ExternalLoginOptions> externalLoginOptions,
        ILogger<AccountController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _accessRevoker = accessRevoker;
        _externalLoginOptions = externalLoginOptions.Value;
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
            // Returning early made "no such account" answer in a fraction of the
            // time a wrong password took, which enumerates valid addresses just
            // as reliably as a distinct error message does. Uses its own hasher
            // so the cost is identical however UserManager is wired.
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
        // disabled case out of the lockout counter.
        var denialReason = UserLifecycle.GetDenialReason(user);
        if (denialReason is not null)
        {
            _logger.LogWarning(
                "Login refused for {Email}: {Reason}", user.Email, denialReason);
            await _auditService.LogAsync(
                "UserLoginFailed", user.Id, user.Email ?? model.Email, user.Id, user.Email,
                $"Login refused: {denialReason}", ipAddress);

            ModelState.AddModelError(string.Empty,
                await DescribeFailureAsync(user, model.Password, AccountDisabledMessage));
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

            ModelState.AddModelError(string.Empty,
                await DescribeFailureAsync(user, model.Password, LockedOutMessage));
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

    /// <summary>
    /// Returns <paramref name="specificMessage"/> when <paramref name="password"/>
    /// is the account's real password, and the generic message otherwise.
    /// </summary>
    /// <remarks>
    /// andy-auth#50. The oracle was that "disabled" and "locked out" were
    /// reachable <em>without</em> knowing the password — so an attacker could
    /// separate real addresses from fake ones, and confirm an account existed
    /// just by tripping its lockout. Gating the disclosure on a correct password
    /// removes that while still telling a legitimate user why they can't get in.
    /// <para>
    /// <see cref="UserManager{TUser}.CheckPasswordAsync"/> verifies the hash
    /// without touching the lockout counter, so probing here cannot itself lock
    /// an account or extend a lockout. It also keeps every path at roughly one
    /// PBKDF2 verification, which closes the timing side of the oracle.
    /// </para>
    /// </remarks>
    private async Task<string> DescribeFailureAsync(
        ApplicationUser user, string password, string specificMessage)
    {
        var passwordIsCorrect = await _userManager.CheckPasswordAsync(user, password ?? string.Empty);
        return passwordIsCorrect ? specificMessage : GenericLoginFailureMessage;
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

        // Logout is an account-wide operation on this surface. Coordinate the
        // browser cookie with OpenIddict tokens/authorizations and every
        // tracked session so a reference refresh token cannot silently keep
        // the account signed in after the UI says logout succeeded (#172).
        if (user != null)
        {
            await _accessRevoker.RevokeAllAccessAsync(user, "User logged out");
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
    ///
    /// Closes andy-auth#119. The external identity is NEVER auto-linked to an
    /// existing local account by matching email alone. The flow has three
    /// distinct outcomes:
    ///  1. The external login is ALREADY linked to a local account: sign the
    ///     user in via <see cref="SignInManager{TUser}.ExternalLoginSignInAsync"/>.
    ///     Local 2FA is enforced unless <see cref="ExternalLoginOptions.BypassLocalTwoFactor"/>
    ///     is explicitly enabled (we do NOT silently bypass it).
    ///  2. No local account has this email: auto-provision a new account bound
    ///     to the external identity (this is not "linking to an existing
    ///     account"). Requires a verified email and an allowed tenant/issuer.
    ///  3. An existing local account shares the email but the login is not
    ///     linked: refuse to auto-link. If the request carries an authenticated
    ///     session for that SAME user, route to an explicit link-confirmation
    ///     (reauthentication) flow; otherwise reject and emit an audit event.
    ///
    /// User-state invariants (disabled/suspended/deleted/expired) are enforced
    /// before any sign-in or link, because ASP.NET Identity's sign-in path does
    /// not know about our custom <see cref="ApplicationUser"/> state fields.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
    {
        returnUrl ??= Url.Content("~/");
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (!string.IsNullOrEmpty(remoteError))
        {
            _logger.LogWarning("External login error: {Error}", remoteError);
            return await RejectExternalAsync(returnUrl, $"Error from external provider: {remoteError}");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            _logger.LogWarning("External login info not available");
            return await RejectExternalAsync(returnUrl, "Error loading external login information.");
        }

        // === Outcome 1: the external login is ALREADY linked to a local account. ===
        var linkedUser = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (linkedUser != null)
        {
            // Enforce user-state invariants that ExternalLoginSignInAsync does not know about.
            var blockedReason = GetSignInBlockedReason(linkedUser);
            if (blockedReason != null)
            {
                await _auditService.LogAsync(
                    "UserLoginExternalRejected",
                    linkedUser.Id, linkedUser.Email ?? "Unknown", linkedUser.Id, linkedUser.Email,
                    $"Login via {info.LoginProvider} rejected: {blockedReason}", ipAddress);
                return await RejectExternalAsync(returnUrl, blockedReason);
            }

            // Do NOT silently bypass local 2FA. The policy is explicit and
            // defaults to enforcing the local second factor.
            var signInResult = await _signInManager.ExternalLoginSignInAsync(
                info.LoginProvider,
                info.ProviderKey,
                isPersistent: false,
                bypassTwoFactor: _externalLoginOptions.BypassLocalTwoFactor);

            if (signInResult.Succeeded)
            {
                _logger.LogInformation("User {UserId} logged in with {Provider} provider.", linkedUser.Id, info.LoginProvider);

                linkedUser.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(linkedUser);

                await _auditService.LogAsync(
                    "UserLoginExternal",
                    linkedUser.Id, linkedUser.Email ?? "Unknown", linkedUser.Id, linkedUser.Email,
                    $"Login via {info.LoginProvider}", ipAddress);

                return RedirectToLocal(returnUrl);
            }

            if (signInResult.RequiresTwoFactor)
            {
                // Not a rejection: the external cookie is consumed by the 2FA
                // flow, so we deliberately do NOT sign the external scheme out.
                _logger.LogInformation("External login for user {UserId} requires local 2FA.", linkedUser.Id);
                return RedirectToAction(nameof(LoginWith2fa), new { returnUrl });
            }

            if (signInResult.IsLockedOut)
            {
                _logger.LogWarning("User {UserId} account locked out during external login.", linkedUser.Id);
                await _auditService.LogAsync(
                    "UserLoginExternalRejected",
                    linkedUser.Id, linkedUser.Email ?? "Unknown", linkedUser.Id, linkedUser.Email,
                    $"Login via {info.LoginProvider} rejected: account locked out", ipAddress);
                return await RejectExternalAsync(returnUrl, "This account has been locked out. Please try again later.");
            }

            await _auditService.LogAsync(
                "UserLoginExternalRejected",
                linkedUser.Id, linkedUser.Email ?? "Unknown", linkedUser.Id, linkedUser.Email,
                $"Login via {info.LoginProvider} rejected: sign-in not allowed", ipAddress);
            return await RejectExternalAsync(returnUrl, "Unable to sign in with this provider.");
        }

        // === The external login is NOT yet linked to any account. ===
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var name = info.Principal.FindFirstValue(ClaimTypes.Name)
                   ?? info.Principal.FindFirstValue("name")
                   ?? email;

        if (string.IsNullOrEmpty(email))
        {
            _logger.LogWarning("External login did not provide an email address");
            return await RejectExternalAsync(returnUrl, "Email address is required from the external provider.");
        }

        // Verified-email requirement (explicit). Applies to both provisioning a
        // new account and linking to an existing one.
        if (_externalLoginOptions.RequireVerifiedEmail && !IsEmailVerified(info.Principal))
        {
            _logger.LogWarning("External login for {Email} rejected: provider did not assert a verified email.", email);
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                email, email, null, email,
                $"Provider {info.LoginProvider} did not assert a verified email (email_verified)", ipAddress);
            return await RejectExternalAsync(returnUrl,
                "Your email address must be verified by the identity provider before you can sign in.");
        }

        // Tenant / issuer allow-list (explicit).
        var tenantIssuerReason = GetTenantIssuerRejection(info.Principal);
        if (tenantIssuerReason != null)
        {
            _logger.LogWarning("External login for {Email} rejected: {Reason}", email, tenantIssuerReason);
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                email, email, null, email,
                $"{info.LoginProvider}: {tenantIssuerReason}", ipAddress);
            return await RejectExternalAsync(returnUrl,
                "Your organization is not permitted to sign in to this application.");
        }

        var existingByEmail = await _userManager.FindByEmailAsync(email);

        // === Outcome 2: no local account exists for this email — auto-provision. ===
        if (existingByEmail == null)
        {
            var newUser = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true, // Verified by the external provider (checked above).
                FullName = name ?? "",
                CreatedAt = DateTime.UtcNow,
                LastLoginAt = DateTime.UtcNow,
                IsActive = true
            };

            var picture = info.Principal.FindFirstValue("picture")
                          ?? info.Principal.FindFirstValue("urn:google:picture");
            if (!string.IsNullOrEmpty(picture))
            {
                newUser.ProfilePictureUrl = picture;
            }

            var createResult = await _userManager.CreateAsync(newUser);
            if (!createResult.Succeeded)
            {
                foreach (var error in createResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                await SignOutExternalAsync();
                return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
            }

            var addLoginResult = await _userManager.AddLoginAsync(newUser, info);
            if (!addLoginResult.Succeeded)
            {
                // The account was just created and has no password; without the
                // external login it would be an orphaned, unauthenticatable
                // account. Roll it back rather than signing in.
                _logger.LogWarning("Failed to add external login for new user {Email}: {Errors}; rolling back the account.",
                    email, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                await _userManager.DeleteAsync(newUser);
                await _auditService.LogAsync(
                    "ExternalLinkRejected",
                    newUser.Id, newUser.Email ?? email, newUser.Id, newUser.Email,
                    $"Provisioning via {info.LoginProvider} rolled back: could not attach external login", ipAddress);
                return await RejectExternalAsync(returnUrl,
                    "Could not complete sign-in with the external provider. Please try again.");
            }

            _logger.LogInformation("Created new user {Email} via {Provider} external login.", email, info.LoginProvider);
            await _auditService.LogAsync(
                "UserRegisteredExternal",
                newUser.Id, newUser.Email ?? email, newUser.Id, newUser.Email,
                $"New user registered via {info.LoginProvider}", ipAddress);

            await _signInManager.SignInAsync(newUser, isPersistent: false);
            await _auditService.LogAsync(
                "UserLoginExternal",
                newUser.Id, newUser.Email ?? email, newUser.Id, newUser.Email,
                $"Login via {info.LoginProvider}", ipAddress);

            return RedirectToLocal(returnUrl);
        }

        // === Outcome 3: an existing local account shares this email but the ===
        // === external login is NOT linked. NEVER auto-link by email alone.  ===
        var sessionUser = User.Identity?.IsAuthenticated == true
            ? await _userManager.GetUserAsync(User)
            : null;

        if (sessionUser == null || !string.Equals(sessionUser.Id, existingByEmail.Id, StringComparison.Ordinal))
        {
            // No authenticated session for the account being claimed: refuse to
            // create the link and do NOT sign anyone in.
            _logger.LogWarning(
                "Refusing to auto-link {Provider} identity to existing account {Email}: no authenticated session for that user.",
                info.LoginProvider, email);
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                existingByEmail.Id, existingByEmail.Email ?? email, existingByEmail.Id, existingByEmail.Email,
                $"Auto-link of {info.LoginProvider} refused: email matches an existing account but no authenticated session for that user",
                ipAddress);
            return await RejectExternalAsync(returnUrl,
                "An account with this email already exists. Sign in with your existing credentials first, then link this provider from your account settings.");
        }

        // Authenticated as the SAME user. Enforce user-state, then require an
        // explicit ownership challenge (reauthentication) before linking.
        var linkBlockedReason = GetSignInBlockedReason(existingByEmail);
        if (linkBlockedReason != null)
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                existingByEmail.Id, existingByEmail.Email ?? email, existingByEmail.Id, existingByEmail.Email,
                $"Link of {info.LoginProvider} rejected: {linkBlockedReason}", ipAddress);
            return await RejectExternalAsync(returnUrl, linkBlockedReason);
        }

        // The external identity is trusted (verified email + allowed
        // tenant/issuer, checked above) and belongs to the signed-in user. Hand
        // off to the explicit reauthentication step. The link POST re-runs these
        // same trust gates so a rejected identity can never be linked, even if
        // the transient cookie were replayed.
        await _auditService.LogAsync(
            "ExternalLinkRequested",
            existingByEmail.Id, existingByEmail.Email ?? email, existingByEmail.Id, existingByEmail.Email,
            $"Authenticated user requested linking {info.LoginProvider}; reauthentication required", ipAddress);
        return RedirectToAction(nameof(LinkExternalLogin), new { returnUrl });
    }

    /// <summary>
    /// Shows the external-login link confirmation. Requires an authenticated
    /// local session; the user must reauthenticate (see the POST) before the
    /// external identity is attached. Part of andy-auth#119.
    /// </summary>
    [HttpGet]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    public async Task<IActionResult> LinkExternalLogin(string? returnUrl = null)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return RedirectToAction(nameof(Login));
        }

        return View(new LinkExternalLoginViewModel
        {
            Provider = info.ProviderDisplayName ?? info.LoginProvider,
            ReturnUrl = returnUrl
        });
    }

    /// <summary>
    /// Confirms linking the pending external identity to the signed-in account.
    /// The ownership challenge is a password reauthentication: the account owner
    /// must prove they know the local password before the provider is attached.
    /// Part of andy-auth#119.
    /// </summary>
    [HttpPost]
    [Authorize(AuthenticationSchemes = "Identity.Application")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LinkExternalLogin(LinkExternalLoginViewModel model)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            ModelState.AddModelError(string.Empty, "The external login session has expired. Please try again.");
            return View(model);
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Ownership challenge: reauthenticate with the local password.
        var passwordOk = await _userManager.CheckPasswordAsync(user, model.Password);
        if (!passwordOk)
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Reauthentication failed while linking {info.LoginProvider}", ipAddress);
            ModelState.AddModelError(string.Empty, "Incorrect password.");
            return View(model);
        }

        // Defense in depth: the external identity's email must still match the
        // signed-in account, so a session for user A cannot attach an identity
        // whose email belongs to user B.
        var externalEmail = info.Principal.FindFirstValue(ClaimTypes.Email);
        if (!string.IsNullOrEmpty(externalEmail)
            && !string.Equals(externalEmail, user.Email, StringComparison.OrdinalIgnoreCase))
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Link of {info.LoginProvider} rejected: provider email does not match the signed-in account", ipAddress);
            ModelState.AddModelError(string.Empty, "This external account's email does not match your account.");
            return View(model);
        }

        // Re-run the SAME trust gates enforced in the callback. This endpoint is
        // the one that actually calls AddLoginAsync, so it must not rely on the
        // callback having already vetted the identity: a rejected callback does
        // not necessarily sign the external cookie out before this point in
        // every provider/proxy configuration, and the already-linked sign-in
        // path never re-checks these gates. Without this, an unverified-email or
        // disallowed-tenant identity could be linked by replaying the cookie
        // straight into this flow, permanently bypassing the allow-list.
        if (_externalLoginOptions.RequireVerifiedEmail && !IsEmailVerified(info.Principal))
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Link of {info.LoginProvider} rejected: provider did not assert a verified email (email_verified)", ipAddress);
            ModelState.AddModelError(string.Empty,
                "Your email address must be verified by the identity provider before you can link it.");
            return View(model);
        }

        var linkTenantIssuerReason = GetTenantIssuerRejection(info.Principal);
        if (linkTenantIssuerReason != null)
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Link of {info.LoginProvider} rejected: {linkTenantIssuerReason}", ipAddress);
            ModelState.AddModelError(string.Empty,
                "Your organization is not permitted to link this provider.");
            return View(model);
        }

        var blockedReason = GetSignInBlockedReason(user);
        if (blockedReason != null)
        {
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Link of {info.LoginProvider} rejected: {blockedReason}", ipAddress);
            ModelState.AddModelError(string.Empty, blockedReason);
            return View(model);
        }

        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (!addLoginResult.Succeeded)
        {
            _logger.LogWarning("Failed to link external login {Provider} for {Email}: {Errors}",
                info.LoginProvider, user.Email, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
            await _auditService.LogAsync(
                "ExternalLinkRejected",
                user.Id, user.Email ?? "Unknown", user.Id, user.Email,
                $"Link of {info.LoginProvider} failed: {string.Join(", ", addLoginResult.Errors.Select(e => e.Description))}",
                ipAddress);
            foreach (var error in addLoginResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        _logger.LogInformation("User {Email} linked {Provider} to their account.", user.Email, info.LoginProvider);
        await _auditService.LogAsync(
            "ExternalLinkSucceeded",
            user.Id, user.Email ?? "Unknown", user.Id, user.Email,
            $"Linked {info.LoginProvider} to account", ipAddress);

        // Refresh the sign-in so the (rotated) security stamp / cookie reflects
        // the new login, without bypassing local 2FA on future sign-ins.
        await _signInManager.RefreshSignInAsync(user);

        return RedirectToLocal(model.ReturnUrl);
    }

    /// <summary>
    /// Returns a reason string if the user is not permitted to sign in or be
    /// linked (disabled/suspended/deleted/expired), or null if permitted.
    /// Mirrors the state fields on <see cref="ApplicationUser"/>.
    /// </summary>
    private static string? GetSignInBlockedReason(ApplicationUser user)
    {
        if (user.DeletedAt.HasValue)
        {
            return "This account has been deleted.";
        }
        if (!user.IsActive)
        {
            return "This account has been disabled.";
        }
        if (user.IsSuspended)
        {
            return "This account has been suspended.";
        }
        if (user.ExpiresAt.HasValue && user.ExpiresAt.Value <= DateTime.UtcNow)
        {
            return "This account has expired.";
        }
        return null;
    }

    /// <summary>
    /// Whether the external principal asserts a verified email. Recognises the
    /// common OIDC (<c>email_verified</c>), Google (<c>verified_email</c>) and
    /// Microsoft claim spellings.
    /// </summary>
    private static bool IsEmailVerified(ClaimsPrincipal principal)
    {
        var claim = principal.FindFirstValue("email_verified")
                    ?? principal.FindFirstValue("verified_email")
                    ?? principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/emailverified");
        return string.Equals(claim, "true", StringComparison.OrdinalIgnoreCase) || claim == "1";
    }

    /// <summary>
    /// Enforces the configured tenant (<c>tid</c>) and issuer (<c>iss</c>)
    /// allow-lists against the external principal. Returns a rejection reason or
    /// null when the principal is allowed.
    /// </summary>
    private string? GetTenantIssuerRejection(ClaimsPrincipal principal)
    {
        var allowedTenants = _externalLoginOptions.AllowedTenantIds
            .Where(t => !string.IsNullOrWhiteSpace(t) && !string.Equals(t, "common", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (allowedTenants.Count > 0)
        {
            var tid = principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/tenantid")
                      ?? principal.FindFirstValue("tid");
            if (string.IsNullOrEmpty(tid) || !allowedTenants.Contains(tid, StringComparer.OrdinalIgnoreCase))
            {
                return $"Provider tenant '{tid ?? "(none)"}' is not in the allowed tenant list";
            }
        }

        var allowedIssuers = _externalLoginOptions.AllowedIssuers
            .Where(i => !string.IsNullOrWhiteSpace(i))
            .ToList();
        if (allowedIssuers.Count > 0)
        {
            var iss = principal.FindFirstValue("iss")
                      ?? principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/issuer");
            if (string.IsNullOrEmpty(iss) || !allowedIssuers.Contains(iss, StringComparer.OrdinalIgnoreCase))
            {
                return $"Provider issuer '{iss ?? "(none)"}' is not in the allowed issuer list";
            }
        }

        return null;
    }

    /// <summary>
    /// Redirects to a validated local return URL, or to Home when absent/unsafe.
    /// </summary>
    private IActionResult RedirectToLocal(string? returnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }

    /// <summary>
    /// Signs out the transient external authentication cookie. Called on every
    /// external-login rejection so a rejected <see cref="ExternalLoginInfo"/>
    /// cannot be replayed (e.g. directly into the account-link flow). The
    /// legitimate link flow does NOT sign out here — it needs the cookie to
    /// persist through the reauthentication step.
    /// </summary>
    private Task SignOutExternalAsync()
        => HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

    /// <summary>
    /// Standard rejection for the external-login callback: drops the external
    /// cookie, records the model error, and re-renders the login page.
    /// </summary>
    private async Task<IActionResult> RejectExternalAsync(string? returnUrl, string message)
    {
        await SignOutExternalAsync();
        ModelState.AddModelError(string.Empty, message);
        return View("Login", new LoginViewModel { ReturnUrl = returnUrl });
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
    /// <remarks>
    /// andy-auth#53. This was a keyless password-spray endpoint: no antiforgery
    /// token, <c>lockoutOnFailure: false</c>, and a single environment-string
    /// check standing between it and the internet. Two things changed.
    /// <para>
    /// It now refuses any request that did not arrive over loopback, so a
    /// mis-set <c>ASPNETCORE_ENVIRONMENT</c> is no longer sufficient on its own
    /// to expose it — an attacker would also have to be executing on the host.
    /// That still covers the only legitimate caller, Conductor's
    /// <c>DevAutoSignIn</c> over the embedded loopback proxy.
    /// </para>
    /// <para>
    /// Failures also count toward lockout now. Exempting them made this the one
    /// unthrottled password oracle in the system, and made it a strictly easier
    /// target than the real sign-in form it shadows.
    /// </para>
    /// </remarks>
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

        // Second, independent gate (andy-auth#53). RemoteIpAddress is the
        // address resolved by the ForwardedHeaders middleware, which only
        // honours forwarding headers from trusted peers (andy-auth#125) — and
        // in local/embedded modes that trust set is loopback only, so this
        // cannot be spoofed from off-host.
        var remoteIp = HttpContext.Connection.RemoteIpAddress;
        if (remoteIp is null || !IPAddress.IsLoopback(remoteIp))
        {
            _logger.LogWarning(
                "TestLogin refused: request from non-loopback address {RemoteIp}", remoteIp);
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
            lockoutOnFailure: true);

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
