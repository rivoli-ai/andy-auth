using Andy.Auth.Server.Data;
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
[Authorize]
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
            return RedirectToAction(nameof(ShowRecoveryCodes));
        }

        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Generates and shows recovery codes.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ShowRecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        var model = new ShowRecoveryCodesViewModel
        {
            RecoveryCodes = recoveryCodes?.ToArray() ?? Array.Empty<string>()
        };

        return View(model);
    }

    /// <summary>
    /// Regenerates recovery codes.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GenerateRecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        if (!isTwoFactorEnabled)
        {
            TempData["ErrorMessage"] = "Cannot generate recovery codes as you do not have 2FA enabled.";
            return RedirectToAction(nameof(Index));
        }

        return RedirectToAction(nameof(ShowRecoveryCodes));
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

        return View();
    }

    /// <summary>
    /// Disables 2FA for the user.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable2faConfirmed()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
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
    /// Resets the authenticator key.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);

        _logger.LogInformation("User {UserId} has reset their authenticator key.", user.Id);
        TempData["StatusMessage"] = "Your authenticator app key has been reset. You will need to configure your authenticator app using the new key.";

        return RedirectToAction(nameof(EnableAuthenticator));
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
