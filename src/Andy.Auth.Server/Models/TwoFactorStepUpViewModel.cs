using System.ComponentModel.DataAnnotations;

namespace Andy.Auth.Server.Models;

/// <summary>
/// Re-authentication demanded before any change to a user's two-factor
/// configuration (andy-auth#52).
/// </summary>
/// <remarks>
/// Every 2FA mutation used to need nothing but a live cookie, so a stolen
/// session could disable 2FA outright, swap the authenticator secret to the
/// attacker's, or burn the user's recovery codes. Proving knowledge of the
/// password — and, while 2FA is still on, possession of the current
/// authenticator — makes a stolen cookie insufficient on its own.
/// </remarks>
public class TwoFactorStepUpViewModel
{
    [Required(ErrorMessage = "Enter your current password to continue.")]
    [DataType(DataType.Password)]
    [Display(Name = "Current password")]
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>
    /// Current authenticator code. Required only while 2FA is enabled — during
    /// initial enrolment there is nothing to prove possession of yet.
    /// </summary>
    [DataType(DataType.Text)]
    [Display(Name = "Authenticator code")]
    public string? TwoFactorCode { get; set; }

    // ---- presentation, set by the controller ----

    /// <summary>Which POST action this confirmation submits to.</summary>
    public string ActionName { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string SubmitLabel { get; set; } = "Confirm";

    /// <summary>True when the outcome is destructive, for styling.</summary>
    public bool IsDestructive { get; set; }

    /// <summary>Whether to show and require the authenticator code field.</summary>
    public bool RequiresAuthenticatorCode { get; set; }
}
