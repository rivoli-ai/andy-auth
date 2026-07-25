using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using QRCoder;
using System.Text;
using System.Text.Encodings.Web;

namespace Andy.Auth.Server.Controllers;

/// <summary>
/// Controller for managing two-factor authentication.
/// </summary>
[Authorize(AuthenticationSchemes = "Identity.Application")]
public class TwoFactorController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<TwoFactorController> _logger;
    private readonly UrlEncoder _urlEncoder;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    public TwoFactorController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<TwoFactorController> logger,
        UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _urlEncoder = urlEncoder;
    }

    /// <summary>
    /// Shows the 2FA management page.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var model = new TwoFactorIndexViewModel
        {
            HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
            Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
            RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user)
        };

        return View(model);
    }

    /// <summary>
    /// Shows the 2FA setup page with QR code.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var model = await LoadSharedKeyAndQrCodeUriAsync(user);
        return View(model);
    }

    /// <summary>
    /// Verifies the 2FA setup code and enables 2FA.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        if (!ModelState.IsValid)
        {
            var viewModel = await LoadSharedKeyAndQrCodeUriAsync(user);
            viewModel.Code = model.Code;
            return View(viewModel);
        }

        // Strip spaces and hyphens
        var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Code", "Verification code is invalid.");
            var viewModel = await LoadSharedKeyAndQrCodeUriAsync(user);
            viewModel.Code = model.Code;
            return View(viewModel);
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        _logger.LogInformation("User {UserId} has enabled 2FA with an authenticator app.", user.Id);

        TempData["StatusMessage"] = "Your authenticator app has been verified.";

        if (await _userManager.CountRecoveryCodesAsync(user) == 0)
        {
            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            return View("ShowRecoveryCodes", new ShowRecoveryCodesViewModel
            {
                RecoveryCodes = codes?.ToArray() ?? Array.Empty<string>()
            });
        }

        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Confirmation page for regenerating recovery codes.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GenerateRecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            TempData["ErrorMessage"] = "Cannot generate recovery codes as you do not have 2FA enabled.";
            return RedirectToAction(nameof(Index));
        }

        return View("StepUp", await BuildStepUpAsync(user, new TwoFactorStepUpViewModel
        {
            ActionName = nameof(GenerateRecoveryCodes),
            Title = "Generate new recovery codes",
            Description = "Your existing recovery codes will stop working immediately. " +
                          "Confirm it is you before we replace them.",
            SubmitLabel = "Generate new codes",
            IsDestructive = true,
        }));
    }

    /// <summary>
    /// Regenerates recovery codes and displays them.
    /// </summary>
    /// <remarks>
    /// andy-auth#52. Generation used to live behind a GET (<c>ShowRecoveryCodes</c>),
    /// so merely loading a URL — an image tag on any page, a prefetch — silently
    /// voided the user's existing codes. Generation now happens only here, on a
    /// POST carrying an antiforgery token and a re-authentication, and the codes
    /// are rendered directly rather than surfaced through a follow-up GET.
    /// </remarks>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GenerateRecoveryCodes(TwoFactorStepUpViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            TempData["ErrorMessage"] = "Cannot generate recovery codes as you do not have 2FA enabled.";
            return RedirectToAction(nameof(Index));
        }

        if (!await VerifyStepUpAsync(user, model))
        {
            return View("StepUp", await BuildStepUpAsync(user, model));
        }

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        _logger.LogInformation("User {UserId} regenerated their 2FA recovery codes.", user.Id);

        return View("ShowRecoveryCodes", new ShowRecoveryCodesViewModel
        {
            RecoveryCodes = recoveryCodes?.ToArray() ?? Array.Empty<string>()
        });
    }

    /// <summary>
    /// Shows the disable 2FA confirmation page.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Disable2fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return RedirectToAction(nameof(Index));
        }

        return View("StepUp", await BuildStepUpAsync(user, new TwoFactorStepUpViewModel
        {
            ActionName = nameof(Disable2faConfirmed),
            Title = "Disable two-factor authentication",
            Description = "Your account will be protected by your password alone. " +
                          "Confirm it is you before we turn this off.",
            SubmitLabel = "Disable 2FA",
            IsDestructive = true,
        }));
    }

    /// <summary>
    /// Disables 2FA for the user.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable2faConfirmed(TwoFactorStepUpViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        model.ActionName = nameof(Disable2faConfirmed);
        model.Title = "Disable two-factor authentication";
        model.Description = "Your account will be protected by your password alone. " +
                            "Confirm it is you before we turn this off.";
        model.SubmitLabel = "Disable 2FA";
        model.IsDestructive = true;

        if (!await VerifyStepUpAsync(user, model))
        {
            return View("StepUp", await BuildStepUpAsync(user, model));
        }

        var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!disable2faResult.Succeeded)
        {
            TempData["ErrorMessage"] = "An error occurred while disabling 2FA.";
            return RedirectToAction(nameof(Index));
        }

        // Reset authenticator key
        await _userManager.ResetAuthenticatorKeyAsync(user);

        _logger.LogInformation("User {UserId} has disabled 2FA.", user.Id);
        TempData["StatusMessage"] = "Two-factor authentication has been disabled.";

        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Confirmation page for resetting the authenticator key.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ResetAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        return View("StepUp", await BuildStepUpAsync(user, new TwoFactorStepUpViewModel
        {
            ActionName = nameof(ResetAuthenticator),
            Title = "Reset your authenticator key",
            Description = "Your current authenticator app will stop working and 2FA will be " +
                          "switched off until you finish setting up the new key.",
            SubmitLabel = "Reset key",
            IsDestructive = true,
        }));
    }

    /// <summary>
    /// Resets the authenticator key.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetAuthenticator(TwoFactorStepUpViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        model.ActionName = nameof(ResetAuthenticator);
        model.Title = "Reset your authenticator key";
        model.Description = "Your current authenticator app will stop working and 2FA will be " +
                            "switched off until you finish setting up the new key.";
        model.SubmitLabel = "Reset key";
        model.IsDestructive = true;

        if (!await VerifyStepUpAsync(user, model))
        {
            return View("StepUp", await BuildStepUpAsync(user, model));
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);

        _logger.LogInformation("User {UserId} has reset their authenticator key.", user.Id);
        TempData["StatusMessage"] = "Your authenticator app key has been reset. You will need to configure your authenticator app using the new key.";

        return RedirectToAction(nameof(EnableAuthenticator));
    }

    /// <summary>
    /// Fills in whether the authenticator-code field applies, which depends on
    /// whether 2FA is currently on.
    /// </summary>
    private async Task<TwoFactorStepUpViewModel> BuildStepUpAsync(
        ApplicationUser user, TwoFactorStepUpViewModel model)
    {
        model.RequiresAuthenticatorCode = await _userManager.GetTwoFactorEnabledAsync(user);
        model.CurrentPassword = string.Empty;
        model.TwoFactorCode = null;
        return model;
    }

    /// <summary>
    /// Re-authenticates the signed-in user before a 2FA change (andy-auth#52).
    /// Adds a model error and returns false when the proof is insufficient.
    /// </summary>
    /// <remarks>
    /// Always requires the password. Additionally requires a current
    /// authenticator code while 2FA is enabled — otherwise someone holding both
    /// a stolen cookie and a leaked password could still strip the second factor,
    /// which is precisely the protection 2FA exists to provide.
    /// <para>
    /// Failures are deliberately reported as one message. Distinguishing "wrong
    /// password" from "wrong code" tells an attacker which half they already
    /// have.
    /// </para>
    /// </remarks>
    private async Task<bool> VerifyStepUpAsync(ApplicationUser user, TwoFactorStepUpViewModel model)
    {
        var passwordOk = await _userManager.CheckPasswordAsync(user, model.CurrentPassword ?? string.Empty);

        var codeOk = true;
        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            var code = (model.TwoFactorCode ?? string.Empty)
                .Replace(" ", string.Empty)
                .Replace("-", string.Empty);

            codeOk = code.Length > 0 && await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);
        }

        if (passwordOk && codeOk)
        {
            return true;
        }

        _logger.LogWarning(
            "2FA step-up failed for user {UserId} (password ok: {PasswordOk}, code ok: {CodeOk})",
            user.Id, passwordOk, codeOk);

        ModelState.AddModelError(string.Empty,
            "We could not verify it is you. Check your password and authenticator code and try again.");
        return false;
    }

    private async Task<EnableAuthenticatorViewModel> LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user)
    {
        // Load the authenticator key & QR code URI to display on the form
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var email = await _userManager.GetEmailAsync(user);
        var authenticatorUri = GenerateQrCodeUri("Andy Auth", email!, unformattedKey!);

        return new EnableAuthenticatorViewModel
        {
            SharedKey = FormatKey(unformattedKey!),
            AuthenticatorUri = authenticatorUri,
            QrCodeBase64 = GenerateQrCodeBase64(authenticatorUri)
        };
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string issuer, string email, string unformattedKey)
    {
        return string.Format(
            AuthenticatorUriFormat,
            _urlEncoder.Encode(issuer),
            _urlEncoder.Encode(email),
            unformattedKey);
    }

    private static string GenerateQrCodeBase64(string text)
    {
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(text, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrCodeBytes = qrCode.GetGraphic(5);
        return Convert.ToBase64String(qrCodeBytes);
    }
}

// View Models

public class TwoFactorIndexViewModel
{
    public bool HasAuthenticator { get; set; }
    public bool Is2faEnabled { get; set; }
    public int RecoveryCodesLeft { get; set; }
}

public class EnableAuthenticatorViewModel
{
    public string SharedKey { get; set; } = null!;
    public string AuthenticatorUri { get; set; } = null!;
    public string QrCodeBase64 { get; set; } = null!;
    public string? Code { get; set; }
}

public class ShowRecoveryCodesViewModel
{
    public string[] RecoveryCodes { get; set; } = Array.Empty<string>();
}
