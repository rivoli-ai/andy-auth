namespace Andy.Auth.Server.Data;

/// <summary>
/// Initial access token for controlled client registration.
/// Admins issue these tokens to developers who can then register clients.
/// </summary>
public class InitialAccessToken
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Display name for this token (for admin reference).
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Optional description of what this token is for.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Hashed token value (using SHA-256).
    /// The plain-text token is only shown once when created.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Admin user who created this token.
    /// </summary>
    public string CreatedById { get; set; } = string.Empty;

    /// <summary>
    /// Email of the admin who created this token.
    /// </summary>
    public string CreatedByEmail { get; set; } = string.Empty;

    /// <summary>
    /// When the token was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the token expires. Null means it never expires.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Whether this token can be used multiple times.
    /// If false, the token is invalidated after first use.
    /// </summary>
    public bool IsMultiUse { get; set; } = false;

    /// <summary>
    /// Maximum number of times this token can be used (for multi-use tokens).
    /// Null means unlimited uses (until expiration).
    /// </summary>
    public int? MaxUses { get; set; }

    /// <summary>
    /// Number of times this token has been used.
    /// </summary>
    public int UseCount { get; set; } = 0;

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
    /// Check if the token is valid (not expired, not revoked, and within use limits).
    /// </summary>
    public bool IsValid =>
        !IsRevoked &&
        (ExpiresAt == null || ExpiresAt > DateTime.UtcNow) &&
        (IsMultiUse || UseCount == 0) &&
        (MaxUses == null || UseCount < MaxUses);
}
