using System.ComponentModel.DataAnnotations;

namespace Andy.Auth.Server.Models;

/// <summary>
/// View model for the change password page.
/// Used when users must change their password on first login or voluntarily.
/// </summary>
public class ChangePasswordViewModel
{
    /// <summary>
    /// Current password — must be re-entered to authorise the change.
    /// Closes andy-auth#45: previously the controller called
    /// GeneratePasswordResetTokenAsync + ResetPasswordAsync, which let any
    /// authenticated session change the password without proving knowledge
    /// of the existing one. Stolen-cookie attackers could pivot to full
    /// account takeover.
    /// </summary>
    [Required(ErrorMessage = "Current password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "Current Password")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "New password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters")]
    [DataType(DataType.Password)]
    [Display(Name = "New Password")]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>
    /// URL to redirect to after successful password change.
    /// </summary>
    public string? ReturnUrl { get; set; }
}
