using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;

namespace Andy.Auth.Server.Tests.Services;

public class SessionServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<ILogger<SessionService>> _loggerMock;
    private readonly IConfiguration _configuration;
    private readonly SessionService _service;

    public SessionServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _loggerMock = new Mock<ILogger<SessionService>>();

        var configValues = new Dictionary<string, string?>
        {
            ["SessionManagement:MaxConcurrentSessions"] = "5",
            ["SessionManagement:SessionTimeout"] = "30.00:00:00",
            ["SessionManagement:InactivityTimeout"] = "7.00:00:00"
        };
        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        _service = new SessionService(_context, _loggerMock.Object, _configuration);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== CreateSessionAsync Tests ====================

    [Fact]
    public async Task CreateSessionAsync_CreatesNewSession()
    {
        // Arrange
        var userId = "user-1";
        var sessionId = Guid.NewGuid().ToString();
        var ipAddress = "192.168.1.1";
        var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0";

        // Act
        var session = await _service.CreateSessionAsync(userId, sessionId, ipAddress, userAgent);

        // Assert
        session.Should().NotBeNull();
        session.UserId.Should().Be(userId);
        session.SessionId.Should().Be(sessionId);
        session.IpAddress.Should().Be(ipAddress);
        session.UserAgent.Should().Be(userAgent);
        session.DeviceInfo.Should().Be("Windows");
        session.IsRevoked.Should().BeFalse();
        session.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        session.LastActivity.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        session.ExpiresAt.Should().BeCloseTo(DateTime.UtcNow.AddDays(30), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task CreateSessionAsync_EnforcesConcurrentLimit_RevokesOldestSession()
    {
        // Arrange
        var userId = "user-1";

        // Create 5 sessions (max limit)
        for (int i = 0; i < 5; i++)
        {
            await _service.CreateSessionAsync(userId, $"session-{i}", null, null);
            await Task.Delay(10); // Ensure different LastActivity times
        }

        var existingSessions = await _context.UserSessions.Where(s => s.UserId == userId).ToListAsync();
        existingSessions.Should().HaveCount(5);

        // Act - Create 6th session
        var newSession = await _service.CreateSessionAsync(userId, "session-new", null, null);

        // Assert
        var allSessions = await _context.UserSessions.Where(s => s.UserId == userId).ToListAsync();
        var activeSessions = allSessions.Where(s => !s.IsRevoked).ToList();
        var revokedSessions = allSessions.Where(s => s.IsRevoked).ToList();

        activeSessions.Should().HaveCount(5);
        revokedSessions.Should().HaveCount(1);
        revokedSessions.First().SessionId.Should().Be("session-0"); // Oldest
        revokedSessions.First().RevocationReason.Should().Be("Concurrent session limit exceeded");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_iPhone()
    {
        // Arrange
        var userAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("iPhone");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_iPad()
    {
        // Arrange
        var userAgent = "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("iPad");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_AndroidPhone()
    {
        // Arrange
        var userAgent = "Mozilla/5.0 (Linux; Android 11; Pixel 5) Mobile";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("Android Phone");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_AndroidTablet()
    {
        // Arrange
        var userAgent = "Mozilla/5.0 (Linux; Android 11; SM-T870)";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("Android Tablet");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_Mac()
    {
        // Arrange
        var userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0)";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("Mac");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_Linux()
    {
        // Arrange
        var userAgent = "Mozilla/5.0 (X11; Linux x86_64)";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("Linux");
    }

    [Fact]
    public async Task CreateSessionAsync_ParsesDeviceInfo_Unknown()
    {
        // Arrange
        var userAgent = "SomeUnknownBrowser/1.0";

        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, userAgent);

        // Assert
        session.DeviceInfo.Should().Be("Unknown");
    }

    [Fact]
    public async Task CreateSessionAsync_NullUserAgent_ReturnsNullDeviceInfo()
    {
        // Act
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);

        // Assert
        session.DeviceInfo.Should().BeNull();
    }

    // ==================== UpdateActivityAsync Tests ====================

    [Fact]
    public async Task UpdateActivityAsync_UpdatesLastActivity()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        var originalActivity = session.LastActivity;
        await Task.Delay(100);

        // Act
        await _service.UpdateActivityAsync("session-1");

        // Assert
        var updatedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-1");
        updatedSession.LastActivity.Should().BeAfter(originalActivity);
    }

    [Fact]
    public async Task UpdateActivityAsync_ExtendsExpirationWithinExtensionWindow()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);

        // Set expiration to within extension window (less than 7 days)
        session.ExpiresAt = DateTime.UtcNow.AddDays(3);
        await _context.SaveChangesAsync();

        var originalExpiration = session.ExpiresAt;

        // Act
        await _service.UpdateActivityAsync("session-1");

        // Assert
        var updatedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-1");
        updatedSession.ExpiresAt.Should().BeAfter(originalExpiration);
    }

    [Fact]
    public async Task UpdateActivityAsync_DoesNotExtendExpirationOutsideWindow()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        var originalExpiration = session.ExpiresAt;

        // Act
        await _service.UpdateActivityAsync("session-1");

        // Assert - Expiration should remain ~30 days out (within extension tolerance)
        var updatedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-1");
        updatedSession.ExpiresAt.Should().BeCloseTo(originalExpiration, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task UpdateActivityAsync_IgnoresRevokedSession()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        session.IsRevoked = true;
        await _context.SaveChangesAsync();

        var originalActivity = session.LastActivity;

        // Act
        await _service.UpdateActivityAsync("session-1");

        // Assert
        var updatedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-1");
        updatedSession.LastActivity.Should().Be(originalActivity);
    }

    [Fact]
    public async Task UpdateActivityAsync_HandlesNonExistentSession()
    {
        // Act & Assert - Should not throw
        await _service.UpdateActivityAsync("non-existent");
    }

    // ==================== GetActiveSessionsAsync Tests ====================

    [Fact]
    public async Task GetActiveSessionsAsync_ReturnsOnlyActiveSessions()
    {
        // Arrange
        var userId = "user-1";
        await _service.CreateSessionAsync(userId, "session-1", null, null);
        await _service.CreateSessionAsync(userId, "session-2", null, null);
        await _service.CreateSessionAsync("user-2", "session-3", null, null); // Different user

        var revokedSession = await _service.CreateSessionAsync(userId, "session-revoked", null, null);
        revokedSession.IsRevoked = true;
        await _context.SaveChangesAsync();

        var expiredSession = await _service.CreateSessionAsync(userId, "session-expired", null, null);
        expiredSession.ExpiresAt = DateTime.UtcNow.AddDays(-1);
        await _context.SaveChangesAsync();

        // Act
        var sessions = await _service.GetActiveSessionsAsync(userId);

        // Assert
        sessions.Should().HaveCount(2);
        sessions.Should().Contain(s => s.SessionId == "session-1");
        sessions.Should().Contain(s => s.SessionId == "session-2");
    }

    [Fact]
    public async Task GetActiveSessionsAsync_ReturnsOrderedByLastActivity()
    {
        // Arrange
        var userId = "user-1";
        var session1 = await _service.CreateSessionAsync(userId, "session-1", null, null);
        await Task.Delay(50);
        var session2 = await _service.CreateSessionAsync(userId, "session-2", null, null);
        await Task.Delay(50);
        var session3 = await _service.CreateSessionAsync(userId, "session-3", null, null);

        // Act
        var sessions = await _service.GetActiveSessionsAsync(userId);

        // Assert - Should be ordered by LastActivity descending
        sessions[0].SessionId.Should().Be("session-3");
        sessions[1].SessionId.Should().Be("session-2");
        sessions[2].SessionId.Should().Be("session-1");
    }

    // ==================== GetSessionAsync Tests ====================

    [Fact]
    public async Task GetSessionAsync_ReturnsSession()
    {
        // Arrange
        await _service.CreateSessionAsync("user-1", "session-1", "192.168.1.1", null);

        // Act
        var session = await _service.GetSessionAsync("session-1");

        // Assert
        session.Should().NotBeNull();
        session!.SessionId.Should().Be("session-1");
        session.IpAddress.Should().Be("192.168.1.1");
    }

    [Fact]
    public async Task GetSessionAsync_ReturnsNullForNonExistent()
    {
        // Act
        var session = await _service.GetSessionAsync("non-existent");

        // Assert
        session.Should().BeNull();
    }

    // ==================== RevokeSessionAsync Tests ====================

    [Fact]
    public async Task RevokeSessionAsync_RevokesSession()
    {
        // Arrange
        var userId = "user-1";
        var session = await _service.CreateSessionAsync(userId, "session-1", null, null);

        // Act
        var result = await _service.RevokeSessionAsync(session.Id, userId, "User requested");

        // Assert
        result.Should().BeTrue();
        var revokedSession = await _context.UserSessions.FirstAsync(s => s.Id == session.Id);
        revokedSession.IsRevoked.Should().BeTrue();
        revokedSession.RevokedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        revokedSession.RevocationReason.Should().Be("User requested");
    }

    [Fact]
    public async Task RevokeSessionAsync_ReturnsFalseForNonExistent()
    {
        // Act
        var result = await _service.RevokeSessionAsync(999, "user-1", "Test");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task RevokeSessionAsync_ReturnsFalseForWrongUser()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);

        // Act
        var result = await _service.RevokeSessionAsync(session.Id, "user-2", "Test");

        // Assert
        result.Should().BeFalse();
    }

    // ==================== RevokeSessionByIdAsync Tests ====================

    [Fact]
    public async Task RevokeSessionByIdAsync_RevokesSession()
    {
        // Arrange
        await _service.CreateSessionAsync("user-1", "session-1", null, null);

        // Act
        var result = await _service.RevokeSessionByIdAsync("session-1", "Admin revoked");

        // Assert
        result.Should().BeTrue();
        var revokedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-1");
        revokedSession.IsRevoked.Should().BeTrue();
        revokedSession.RevocationReason.Should().Be("Admin revoked");
    }

    [Fact]
    public async Task RevokeSessionByIdAsync_ReturnsFalseForNonExistent()
    {
        // Act
        var result = await _service.RevokeSessionByIdAsync("non-existent", "Test");

        // Assert
        result.Should().BeFalse();
    }

    // ==================== RevokeAllOtherSessionsAsync Tests ====================

    [Fact]
    public async Task RevokeAllOtherSessionsAsync_RevokesAllExceptCurrent()
    {
        // Arrange
        var userId = "user-1";
        await _service.CreateSessionAsync(userId, "session-1", null, null);
        await _service.CreateSessionAsync(userId, "session-2", null, null);
        await _service.CreateSessionAsync(userId, "session-3", null, null);

        // Act
        var count = await _service.RevokeAllOtherSessionsAsync(userId, "session-2");

        // Assert
        count.Should().Be(2);
        var sessions = await _context.UserSessions.Where(s => s.UserId == userId).ToListAsync();
        sessions.Single(s => s.SessionId == "session-1").IsRevoked.Should().BeTrue();
        sessions.Single(s => s.SessionId == "session-2").IsRevoked.Should().BeFalse();
        sessions.Single(s => s.SessionId == "session-3").IsRevoked.Should().BeTrue();
    }

    [Fact]
    public async Task RevokeAllOtherSessionsAsync_DoesNotRevokeAlreadyRevoked()
    {
        // Arrange
        var userId = "user-1";
        await _service.CreateSessionAsync(userId, "session-1", null, null);
        var session2 = await _service.CreateSessionAsync(userId, "session-2", null, null);
        session2.IsRevoked = true;
        await _context.SaveChangesAsync();
        await _service.CreateSessionAsync(userId, "session-current", null, null);

        // Act
        var count = await _service.RevokeAllOtherSessionsAsync(userId, "session-current");

        // Assert
        count.Should().Be(1); // Only session-1 should be revoked
    }

    // ==================== RevokeAllSessionsAsync Tests ====================

    [Fact]
    public async Task RevokeAllSessionsAsync_RevokesAllSessions()
    {
        // Arrange
        var userId = "user-1";
        await _service.CreateSessionAsync(userId, "session-1", null, null);
        await _service.CreateSessionAsync(userId, "session-2", null, null);
        await _service.CreateSessionAsync(userId, "session-3", null, null);

        // Act
        var count = await _service.RevokeAllSessionsAsync(userId, "User logout");

        // Assert
        count.Should().Be(3);
        var sessions = await _context.UserSessions.Where(s => s.UserId == userId).ToListAsync();
        sessions.Should().OnlyContain(s => s.IsRevoked);
        sessions.Should().OnlyContain(s => s.RevocationReason == "User logout");
    }

    [Fact]
    public async Task RevokeAllSessionsAsync_ReturnsZeroWhenNoActiveSessions()
    {
        // Arrange
        var userId = "user-1";

        // Act
        var count = await _service.RevokeAllSessionsAsync(userId, "Test");

        // Assert
        count.Should().Be(0);
    }

    // ==================== IsSessionValidAsync Tests ====================

    [Fact]
    public async Task IsSessionValidAsync_ReturnsTrueForValidSession()
    {
        // Arrange
        await _service.CreateSessionAsync("user-1", "session-1", null, null);

        // Act
        var isValid = await _service.IsSessionValidAsync("session-1");

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task IsSessionValidAsync_ReturnsFalseForNonExistent()
    {
        // Act
        var isValid = await _service.IsSessionValidAsync("non-existent");

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task IsSessionValidAsync_ReturnsFalseForRevokedSession()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        session.IsRevoked = true;
        await _context.SaveChangesAsync();

        // Act
        var isValid = await _service.IsSessionValidAsync("session-1");

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task IsSessionValidAsync_ReturnsFalseForExpiredSession()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        session.ExpiresAt = DateTime.UtcNow.AddDays(-1);
        await _context.SaveChangesAsync();

        // Act
        var isValid = await _service.IsSessionValidAsync("session-1");

        // Assert
        isValid.Should().BeFalse();
    }

    [Fact]
    public async Task IsSessionValidAsync_ReturnsFalseForInactiveSession()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        session.LastActivity = DateTime.UtcNow.AddDays(-8); // Beyond 7-day inactivity timeout
        await _context.SaveChangesAsync();

        // Act
        var isValid = await _service.IsSessionValidAsync("session-1");

        // Assert
        isValid.Should().BeFalse();

        // Verify session was marked as revoked due to inactivity
        var updatedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-1");
        updatedSession.IsRevoked.Should().BeTrue();
        updatedSession.RevocationReason.Should().Be("Inactivity timeout");
    }

    // ==================== CleanupExpiredSessionsAsync Tests ====================

    [Fact]
    public async Task CleanupExpiredSessionsAsync_MarksExpiredSessionsAsRevoked()
    {
        // Arrange
        await _service.CreateSessionAsync("user-1", "session-valid", null, null);

        var expiredSession1 = await _service.CreateSessionAsync("user-1", "session-expired-1", null, null);
        expiredSession1.ExpiresAt = DateTime.UtcNow.AddDays(-1);

        var expiredSession2 = await _service.CreateSessionAsync("user-2", "session-expired-2", null, null);
        expiredSession2.ExpiresAt = DateTime.UtcNow.AddHours(-1);

        await _context.SaveChangesAsync();

        // Act
        var count = await _service.CleanupExpiredSessionsAsync();

        // Assert
        count.Should().Be(2);

        var session1 = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-expired-1");
        session1.IsRevoked.Should().BeTrue();
        session1.RevocationReason.Should().Be("Session expired");

        var session2 = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-expired-2");
        session2.IsRevoked.Should().BeTrue();

        var validSession = await _context.UserSessions.FirstAsync(s => s.SessionId == "session-valid");
        validSession.IsRevoked.Should().BeFalse();
    }

    [Fact]
    public async Task CleanupExpiredSessionsAsync_ReturnsZeroWhenNoExpiredSessions()
    {
        // Arrange
        await _service.CreateSessionAsync("user-1", "session-1", null, null);

        // Act
        var count = await _service.CleanupExpiredSessionsAsync();

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public async Task CleanupExpiredSessionsAsync_SkipsAlreadyRevokedSessions()
    {
        // Arrange
        var session = await _service.CreateSessionAsync("user-1", "session-1", null, null);
        session.ExpiresAt = DateTime.UtcNow.AddDays(-1);
        session.IsRevoked = true;
        await _context.SaveChangesAsync();

        // Act
        var count = await _service.CleanupExpiredSessionsAsync();

        // Assert
        count.Should().Be(0);
    }

    // ==================== GetUserSessionStatsAsync Tests ====================

    [Fact]
    public async Task GetUserSessionStatsAsync_ReturnsCorrectStats()
    {
        // Arrange
        var userId = "user-1";

        // Active sessions
        await _service.CreateSessionAsync(userId, "session-1", null, null);
        await _service.CreateSessionAsync(userId, "session-2", null, null);

        // Revoked session
        var revokedSession = await _service.CreateSessionAsync(userId, "session-revoked", null, null);
        revokedSession.IsRevoked = true;
        await _context.SaveChangesAsync();

        // Expired session (not revoked)
        var expiredSession = await _service.CreateSessionAsync(userId, "session-expired", null, null);
        expiredSession.ExpiresAt = DateTime.UtcNow.AddDays(-1);
        await _context.SaveChangesAsync();

        // Act
        var stats = await _service.GetUserSessionStatsAsync(userId);

        // Assert
        stats.TotalSessions.Should().Be(4);
        stats.ActiveSessions.Should().Be(2);
        stats.RevokedSessions.Should().Be(1);
        stats.ExpiredSessions.Should().Be(1);
    }

    [Fact]
    public async Task GetUserSessionStatsAsync_ReturnsZerosForNewUser()
    {
        // Act
        var stats = await _service.GetUserSessionStatsAsync("new-user");

        // Assert
        stats.TotalSessions.Should().Be(0);
        stats.ActiveSessions.Should().Be(0);
        stats.RevokedSessions.Should().Be(0);
        stats.ExpiredSessions.Should().Be(0);
    }

    // ==================== Configuration Tests ====================

    [Fact]
    public void MaxConcurrentSessions_ReturnsConfiguredValue()
    {
        // Assert
        _service.MaxConcurrentSessions.Should().Be(5);
    }

    [Fact]
    public void SessionTimeout_ReturnsConfiguredValue()
    {
        // Assert
        _service.SessionTimeout.Should().Be(TimeSpan.FromDays(30));
    }

    [Fact]
    public void InactivityTimeout_ReturnsConfiguredValue()
    {
        // Assert
        _service.InactivityTimeout.Should().Be(TimeSpan.FromDays(7));
    }

    [Fact]
    public void Configuration_UsesDefaultsWhenNotConfigured()
    {
        // Arrange
        var emptyConfig = new ConfigurationBuilder().Build();
        var serviceWithDefaults = new SessionService(_context, _loggerMock.Object, emptyConfig);

        // Assert
        serviceWithDefaults.MaxConcurrentSessions.Should().Be(5);
        serviceWithDefaults.SessionTimeout.Should().Be(TimeSpan.FromDays(30));
        serviceWithDefaults.InactivityTimeout.Should().Be(TimeSpan.FromDays(7));
    }
}
