using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Service for managing user sessions.
/// </summary>
public class SessionService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<SessionService> _logger;
    private readonly IConfiguration _configuration;

    public SessionService(
        ApplicationDbContext dbContext,
        ILogger<SessionService> logger,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _logger = logger;
        _configuration = configuration;
    }

    /// <summary>
    /// Gets the maximum allowed concurrent sessions per user.
    /// </summary>
    public int MaxConcurrentSessions =>
        _configuration.GetValue("SessionManagement:MaxConcurrentSessions", 5);

    /// <summary>
    /// Gets the session timeout duration.
    /// </summary>
    public TimeSpan SessionTimeout =>
        _configuration.GetValue("SessionManagement:SessionTimeout", TimeSpan.FromDays(30));

    /// <summary>
    /// Gets the inactivity timeout duration.
    /// </summary>
    public TimeSpan InactivityTimeout =>
        _configuration.GetValue("SessionManagement:InactivityTimeout", TimeSpan.FromDays(7));

    /// <summary>
    /// Creates a new session for a user.
    /// </summary>
    public async Task<UserSession> CreateSessionAsync(
        string userId,
        string sessionId,
        string? ipAddress,
        string? userAgent)
    {
        // Enforce concurrent session limit
        await EnforceConcurrentSessionLimitAsync(userId);

        var session = new UserSession
        {
            UserId = userId,
            SessionId = sessionId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            DeviceInfo = ParseDeviceInfo(userAgent),
            CreatedAt = DateTime.UtcNow,
            LastActivity = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(SessionTimeout)
        };

        _dbContext.UserSessions.Add(session);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation(
            "Created session {SessionId} for user {UserId} from {IpAddress}",
            sessionId, userId, ipAddress);

        return session;
    }

    /// <summary>
    /// Updates the last activity time for a session.
    /// </summary>
    public async Task UpdateActivityAsync(string sessionId)
    {
        var session = await _dbContext.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == sessionId && !s.IsRevoked);

        if (session != null)
        {
            session.LastActivity = DateTime.UtcNow;

            // Extend expiration if within extension window
            var extensionThreshold = session.ExpiresAt.Subtract(TimeSpan.FromDays(7));
            if (DateTime.UtcNow > extensionThreshold)
            {
                session.ExpiresAt = DateTime.UtcNow.Add(SessionTimeout);
            }

            await _dbContext.SaveChangesAsync();
        }
    }

    /// <summary>
    /// Gets all active sessions for a user.
    /// </summary>
    public async Task<List<UserSession>> GetActiveSessionsAsync(string userId)
    {
        return await _dbContext.UserSessions
            .Where(s => s.UserId == userId && !s.IsRevoked && s.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(s => s.LastActivity)
            .ToListAsync();
    }

    /// <summary>
    /// Gets a session by its ID.
    /// </summary>
    public async Task<UserSession?> GetSessionAsync(string sessionId)
    {
        return await _dbContext.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == sessionId);
    }

    /// <summary>
    /// Revokes a specific session.
    /// </summary>
    public async Task<bool> RevokeSessionAsync(int sessionId, string userId, string reason)
    {
        var session = await _dbContext.UserSessions
            .FirstOrDefaultAsync(s => s.Id == sessionId && s.UserId == userId);

        if (session == null)
            return false;

        session.IsRevoked = true;
        session.RevokedAt = DateTime.UtcNow;
        session.RevocationReason = reason;

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation(
            "Revoked session {SessionId} for user {UserId}. Reason: {Reason}",
            session.SessionId, userId, reason);

        return true;
    }

    /// <summary>
    /// Revokes a session by its session ID string.
    /// </summary>
    public async Task<bool> RevokeSessionByIdAsync(string sessionId, string reason)
    {
        var session = await _dbContext.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == sessionId);

        if (session == null)
            return false;

        session.IsRevoked = true;
        session.RevokedAt = DateTime.UtcNow;
        session.RevocationReason = reason;

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation(
            "Revoked session {SessionId}. Reason: {Reason}",
            sessionId, reason);

        return true;
    }

    /// <summary>
    /// Revokes all sessions for a user except the current one.
    /// </summary>
    public async Task<int> RevokeAllOtherSessionsAsync(string userId, string currentSessionId)
    {
        var sessions = await _dbContext.UserSessions
            .Where(s => s.UserId == userId && !s.IsRevoked && s.SessionId != currentSessionId)
            .ToListAsync();

        foreach (var session in sessions)
        {
            session.IsRevoked = true;
            session.RevokedAt = DateTime.UtcNow;
            session.RevocationReason = "User revoked all other sessions";
        }

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation(
            "Revoked {Count} other sessions for user {UserId}",
            sessions.Count, userId);

        return sessions.Count;
    }

    /// <summary>
    /// Revokes all sessions for a user (on logout).
    /// </summary>
    public async Task<int> RevokeAllSessionsAsync(string userId, string reason)
    {
        var sessions = await _dbContext.UserSessions
            .Where(s => s.UserId == userId && !s.IsRevoked)
            .ToListAsync();

        foreach (var session in sessions)
        {
            session.IsRevoked = true;
            session.RevokedAt = DateTime.UtcNow;
            session.RevocationReason = reason;
        }

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation(
            "Revoked all {Count} sessions for user {UserId}. Reason: {Reason}",
            sessions.Count, userId, reason);

        return sessions.Count;
    }

    /// <summary>
    /// Validates if a session is still active.
    /// </summary>
    public async Task<bool> IsSessionValidAsync(string sessionId)
    {
        var session = await _dbContext.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == sessionId);

        if (session == null)
            return false;

        // Check if revoked
        if (session.IsRevoked)
            return false;

        // Check if expired
        if (session.ExpiresAt <= DateTime.UtcNow)
            return false;

        // Check inactivity timeout
        var inactivityLimit = session.LastActivity.Add(InactivityTimeout);
        if (DateTime.UtcNow > inactivityLimit)
        {
            // Mark as expired due to inactivity
            session.IsRevoked = true;
            session.RevokedAt = DateTime.UtcNow;
            session.RevocationReason = "Inactivity timeout";
            await _dbContext.SaveChangesAsync();
            return false;
        }

        return true;
    }

    /// <summary>
    /// Cleans up expired sessions from the database.
    /// </summary>
    public async Task<int> CleanupExpiredSessionsAsync()
    {
        var cutoff = DateTime.UtcNow;
        var expiredSessions = await _dbContext.UserSessions
            .Where(s => !s.IsRevoked && s.ExpiresAt <= cutoff)
            .ToListAsync();

        foreach (var session in expiredSessions)
        {
            session.IsRevoked = true;
            session.RevokedAt = DateTime.UtcNow;
            session.RevocationReason = "Session expired";
        }

        await _dbContext.SaveChangesAsync();

        if (expiredSessions.Count > 0)
        {
            _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
        }

        return expiredSessions.Count;
    }

    /// <summary>
    /// Gets session statistics for a user (for admin view).
    /// </summary>
    public async Task<SessionStats> GetUserSessionStatsAsync(string userId)
    {
        var sessions = await _dbContext.UserSessions
            .Where(s => s.UserId == userId)
            .ToListAsync();

        return new SessionStats
        {
            TotalSessions = sessions.Count,
            ActiveSessions = sessions.Count(s => s.IsValid),
            RevokedSessions = sessions.Count(s => s.IsRevoked),
            ExpiredSessions = sessions.Count(s => !s.IsRevoked && s.ExpiresAt <= DateTime.UtcNow)
        };
    }

    private async Task EnforceConcurrentSessionLimitAsync(string userId)
    {
        var activeSessions = await _dbContext.UserSessions
            .Where(s => s.UserId == userId && !s.IsRevoked && s.ExpiresAt > DateTime.UtcNow)
            .OrderBy(s => s.LastActivity)
            .ToListAsync();

        // If at or over limit, revoke oldest sessions
        var sessionsToRevoke = activeSessions.Count - MaxConcurrentSessions + 1;
        if (sessionsToRevoke > 0)
        {
            var oldestSessions = activeSessions.Take(sessionsToRevoke);
            foreach (var session in oldestSessions)
            {
                session.IsRevoked = true;
                session.RevokedAt = DateTime.UtcNow;
                session.RevocationReason = "Concurrent session limit exceeded";

                _logger.LogInformation(
                    "Revoked session {SessionId} for user {UserId} due to concurrent session limit",
                    session.SessionId, userId);
            }

            await _dbContext.SaveChangesAsync();
        }
    }

    private static string? ParseDeviceInfo(string? userAgent)
    {
        if (string.IsNullOrEmpty(userAgent))
            return null;

        // Simple device detection
        if (userAgent.Contains("iPhone"))
            return "iPhone";
        if (userAgent.Contains("iPad"))
            return "iPad";
        if (userAgent.Contains("Android"))
        {
            if (userAgent.Contains("Mobile"))
                return "Android Phone";
            return "Android Tablet";
        }
        if (userAgent.Contains("Windows"))
            return "Windows";
        if (userAgent.Contains("Macintosh"))
            return "Mac";
        if (userAgent.Contains("Linux"))
            return "Linux";

        return "Unknown";
    }
}

/// <summary>
/// Statistics about user sessions.
/// </summary>
public class SessionStats
{
    public int TotalSessions { get; set; }
    public int ActiveSessions { get; set; }
    public int RevokedSessions { get; set; }
    public int ExpiredSessions { get; set; }
}
