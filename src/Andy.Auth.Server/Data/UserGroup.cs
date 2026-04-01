namespace Andy.Auth.Server.Data;

/// <summary>
/// Join table linking users to groups.
/// </summary>
public class UserGroup
{
    public Guid Id { get; set; }

    /// <summary>
    /// The user ID (references ApplicationUser).
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// The group ID.
    /// </summary>
    public Guid GroupId { get; set; }

    /// <summary>
    /// When the user was added to the group.
    /// </summary>
    public DateTime JoinedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Optional expiration date for temporary group membership.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Source of the membership: "manual" or "sync" (from LDAP/AD).
    /// </summary>
    public string Source { get; set; } = "manual";

    // Navigation properties
    public ApplicationUser User { get; set; } = null!;
    public Group Group { get; set; } = null!;
}
