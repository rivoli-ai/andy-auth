using System.ComponentModel.DataAnnotations;

namespace Andy.Auth.Server.Models;

/// <summary>
/// View model for the external-login account-linking confirmation. Linking an
/// external identity to an existing local account requires an authenticated
/// session AND reauthentication (the ownership challenge): the signed-in user
/// must re-enter their local password before the provider is attached.
/// </summary>
public class LinkExternalLoginViewModel
{
    /// <summary>
    /// Display name of the external provider being linked (informational).
    /// </summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>
    /// The user's current local password, used to reauthenticate before the
    /// external identity is attached to the account.
    /// </summary>
    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Current password")]
    public string Password { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}
