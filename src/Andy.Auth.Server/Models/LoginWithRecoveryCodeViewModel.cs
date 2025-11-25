using System.ComponentModel.DataAnnotations;

namespace Andy.Auth.Server.Models;

public class LoginWithRecoveryCodeViewModel
{
    [Required]
    [DataType(DataType.Text)]
    [Display(Name = "Recovery Code")]
    public string RecoveryCode { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}
