using Microsoft.AspNetCore.Identity;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Application user extending ASP.NET Core Identity.
/// </summary>
public class ApplicationUser : IdentityUser
{
    /// <summary>
    /// User's full name.
    /// </summary>
    public string? FullName { get; set; }

    /// <summary>
    /// User's profile picture URL.
    /// </summary>
    public string? ProfilePictureUrl { get; set; }

    /// <summary>
    /// Date when the user was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Date when the user last logged in.
    /// </summary>
    public DateTime? LastLoginAt { get; set; }

    /// <summary>
    /// Whether the user account is active.
    /// </summary>
    public bool IsActive { get; set; } = true;
}
