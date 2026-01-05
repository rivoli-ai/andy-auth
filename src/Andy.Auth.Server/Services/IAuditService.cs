namespace Andy.Auth.Server.Services;

/// <summary>
/// Service for logging audit events across the application.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Logs an audit event.
    /// </summary>
    /// <param name="action">The type of action (e.g., "UserLogin", "UserSuspended").</param>
    /// <param name="performedById">The ID of the user who performed the action.</param>
    /// <param name="performedByEmail">The email of the user who performed the action.</param>
    /// <param name="targetUserId">The ID of the target user (if applicable).</param>
    /// <param name="targetUserEmail">The email of the target user (if applicable).</param>
    /// <param name="details">Additional details about the action.</param>
    /// <param name="ipAddress">The IP address from which the action was performed.</param>
    Task LogAsync(
        string action,
        string performedById,
        string performedByEmail,
        string? targetUserId = null,
        string? targetUserEmail = null,
        string? details = null,
        string? ipAddress = null);
}
