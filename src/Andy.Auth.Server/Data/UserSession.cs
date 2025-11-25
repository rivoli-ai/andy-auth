using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Represents an active user session.
/// Used for server-side session tracking and management.
/// </summary>
public class UserSession
{
    /// <summary>
    /// Unique identifier for the session record.
    /// </summary>
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// The user who owns this session.
    /// </summary>
    [Required]
    [MaxLength(450)]
    public string UserId { get; set; } = null!;

    /// <summary>
    /// Navigation property to the user.
    /// </summary>
    [ForeignKey(nameof(UserId))]
    public ApplicationUser? User { get; set; }

    /// <summary>
    /// Unique session identifier (usually from the authentication cookie).
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string SessionId { get; set; } = null!;

    /// <summary>
    /// Device information (parsed from User-Agent or device fingerprint).
    /// </summary>
    [MaxLength(500)]
    public string? DeviceInfo { get; set; }

    /// <summary>
    /// IP address of the client.
    /// </summary>
    [MaxLength(45)]
    public string? IpAddress { get; set; }

    /// <summary>
    /// Full User-Agent string from the browser.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Geographic location derived from IP (city, country).
    /// </summary>
    [MaxLength(200)]
    public string? Location { get; set; }

    /// <summary>
    /// When the session was created (login time).
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the session was last active.
    /// </summary>
    public DateTime LastActivity { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the session expires.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Whether this session has been explicitly revoked.
    /// </summary>
    public bool IsRevoked { get; set; }

    /// <summary>
    /// When the session was revoked (if applicable).
    /// </summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Reason for revocation (user-initiated, admin-initiated, concurrent limit, etc.).
    /// </summary>
    [MaxLength(200)]
    public string? RevocationReason { get; set; }

    /// <summary>
    /// Checks if the session is currently valid.
    /// </summary>
    [NotMapped]
    public bool IsValid => !IsRevoked && ExpiresAt > DateTime.UtcNow;

    /// <summary>
    /// Gets a friendly description of the device.
    /// </summary>
    [NotMapped]
    public string DeviceDescription
    {
        get
        {
            if (!string.IsNullOrEmpty(DeviceInfo))
                return DeviceInfo;

            if (string.IsNullOrEmpty(UserAgent))
                return "Unknown device";

            // Parse User-Agent for common browsers/devices
            if (UserAgent.Contains("iPhone"))
                return "iPhone";
            if (UserAgent.Contains("iPad"))
                return "iPad";
            if (UserAgent.Contains("Android"))
                return "Android device";
            if (UserAgent.Contains("Windows"))
                return "Windows PC";
            if (UserAgent.Contains("Macintosh"))
                return "Mac";
            if (UserAgent.Contains("Linux"))
                return "Linux";

            return "Web browser";
        }
    }

    /// <summary>
    /// Gets a friendly description of the browser.
    /// </summary>
    [NotMapped]
    public string BrowserDescription
    {
        get
        {
            if (string.IsNullOrEmpty(UserAgent))
                return "Unknown browser";

            if (UserAgent.Contains("Edg/"))
                return "Microsoft Edge";
            if (UserAgent.Contains("Chrome/"))
                return "Google Chrome";
            if (UserAgent.Contains("Firefox/"))
                return "Mozilla Firefox";
            if (UserAgent.Contains("Safari/") && !UserAgent.Contains("Chrome/"))
                return "Safari";
            if (UserAgent.Contains("OPR/") || UserAgent.Contains("Opera/"))
                return "Opera";

            return "Web browser";
        }
    }
}
