namespace Andy.Auth.Server.Data;

/// <summary>
/// Registration access token for managing dynamically registered clients (RFC 7591/7592).
/// This token is issued when a client registers and allows them to read/update/delete their registration.
/// </summary>
public class RegistrationAccessToken
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// The client ID this token is associated with.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Hashed token value (using SHA-256).
    /// The plain-text token is only returned once at registration time.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// When the token was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the token expires. Null means it never expires.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Whether the token has been revoked.
    /// </summary>
    public bool IsRevoked { get; set; } = false;

    /// <summary>
    /// When the token was revoked (if applicable).
    /// </summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Who revoked the token (admin user ID).
    /// </summary>
    public string? RevokedBy { get; set; }

    /// <summary>
    /// Reason for revocation.
    /// </summary>
    public string? RevocationReason { get; set; }

    /// <summary>
    /// Last time this token was used.
    /// </summary>
    public DateTime? LastUsedAt { get; set; }

    /// <summary>
    /// Check if the token is valid (not expired and not revoked).
    /// </summary>
    public bool IsValid => !IsRevoked && (ExpiresAt == null || ExpiresAt > DateTime.UtcNow);
}
