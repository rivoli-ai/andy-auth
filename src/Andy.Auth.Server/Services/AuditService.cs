using Andy.Auth.Server.Data;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Implementation of audit logging service.
/// </summary>
public class AuditService : IAuditService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AuditService> _logger;

    public AuditService(ApplicationDbContext context, ILogger<AuditService> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task LogAsync(
        string action,
        string performedById,
        string performedByEmail,
        string? targetUserId = null,
        string? targetUserEmail = null,
        string? details = null,
        string? ipAddress = null)
    {
        var auditLog = new AuditLog
        {
            Action = action,
            PerformedById = performedById,
            PerformedByEmail = performedByEmail,
            TargetUserId = targetUserId,
            TargetUserEmail = targetUserEmail,
            Details = details,
            PerformedAt = DateTime.UtcNow,
            IpAddress = ipAddress
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Audit: {Action} by {PerformedByEmail} (target: {TargetUserEmail})",
            action,
            performedByEmail,
            targetUserEmail ?? "N/A");
    }
}
