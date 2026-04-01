namespace Andy.Auth.Server.Data;

/// <summary>
/// Represents a group that users can belong to.
/// Groups are included as claims in tokens for RBAC integration.
/// </summary>
public class Group
{
    public Guid Id { get; set; }

    /// <summary>
    /// Unique code identifier for the group (e.g., "engineering", "devops").
    /// This is the value included in the token's groups claim.
    /// </summary>
    public required string Code { get; set; }

    /// <summary>
    /// Display name of the group.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// Optional description of the group.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Whether the group is active. Inactive groups are not included in tokens.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// External identifier for LDAP/AD sync (e.g., LDAP DN or AD ObjectGUID).
    /// Null if group is managed locally.
    /// </summary>
    public string? ExternalId { get; set; }

    /// <summary>
    /// Source of the group: "local" or provider name like "ldap", "azure-ad".
    /// </summary>
    public string Source { get; set; } = "local";

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastSyncedAt { get; set; }

    // Navigation properties
    public ICollection<UserGroup> UserGroups { get; set; } = [];
}
