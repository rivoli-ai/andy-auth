namespace Andy.Auth.Server.Data;

/// <summary>
/// Audit log for tracking administrative actions.
/// </summary>
public class AuditLog
{
    /// <summary>
    /// Unique identifier for the audit log entry.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Type of action performed (e.g., "UserSuspended", "UserDeleted", "UserExpirationSet").
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// ID of the user who performed the action.
    /// </summary>
    public string PerformedById { get; set; } = string.Empty;

    /// <summary>
    /// Email of the user who performed the action.
    /// </summary>
    public string PerformedByEmail { get; set; } = string.Empty;

    /// <summary>
    /// ID of the target user (if applicable).
    /// </summary>
    public string? TargetUserId { get; set; }

    /// <summary>
    /// Email of the target user (if applicable).
    /// </summary>
    public string? TargetUserEmail { get; set; }

    /// <summary>
    /// Additional details about the action (e.g., reason for suspension).
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// Date and time when the action was performed.
    /// </summary>
    public DateTime PerformedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// IP address from which the action was performed.
    /// </summary>
    public string? IpAddress { get; set; }
}
