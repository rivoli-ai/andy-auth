using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;

namespace Andy.Auth.Server.Tests.Services;

public class AuditServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<ILogger<AuditService>> _loggerMock;
    private readonly AuditService _service;

    public AuditServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _loggerMock = new Mock<ILogger<AuditService>>();
        _service = new AuditService(_context, _loggerMock.Object);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    [Fact]
    public async Task LogAsync_SavesAuditLog()
    {
        // Arrange
        var action = "USER_CREATED";
        var performedById = "admin-1";
        var performedByEmail = "admin@test.com";
        var targetUserId = "user-1";
        var targetUserEmail = "user@test.com";
        var details = "Created new user";
        var ipAddress = "192.168.1.1";

        // Act
        await _service.LogAsync(action, performedById, performedByEmail,
            targetUserId, targetUserEmail, details, ipAddress);

        // Assert
        var logs = await _context.AuditLogs.ToListAsync();
        logs.Should().ContainSingle();

        var log = logs.First();
        log.Action.Should().Be(action);
        log.PerformedById.Should().Be(performedById);
        log.PerformedByEmail.Should().Be(performedByEmail);
        log.TargetUserId.Should().Be(targetUserId);
        log.TargetUserEmail.Should().Be(targetUserEmail);
        log.Details.Should().Be(details);
        log.IpAddress.Should().Be(ipAddress);
        log.PerformedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task LogAsync_SavesWithOptionalParametersNull()
    {
        // Arrange
        var action = "SYSTEM_EVENT";
        var performedById = "system";
        var performedByEmail = "system@internal";

        // Act
        await _service.LogAsync(action, performedById, performedByEmail);

        // Assert
        var log = await _context.AuditLogs.SingleAsync();
        log.Action.Should().Be(action);
        log.TargetUserId.Should().BeNull();
        log.TargetUserEmail.Should().BeNull();
        log.Details.Should().BeNull();
        log.IpAddress.Should().BeNull();
    }

    [Fact]
    public async Task LogAsync_SetsCorrectTimestamp()
    {
        // Arrange
        var before = DateTime.UtcNow.AddSeconds(-1);

        // Act
        await _service.LogAsync("TEST_ACTION", "user-1", "user@test.com");

        // Assert
        var log = await _context.AuditLogs.SingleAsync();
        log.PerformedAt.Should().BeAfter(before);
        log.PerformedAt.Should().BeBefore(DateTime.UtcNow.AddSeconds(1));
    }

    [Fact]
    public async Task LogAsync_LogsInformationMessage()
    {
        // Act
        await _service.LogAsync("USER_DELETED", "admin-1", "admin@test.com",
            "user-1", "deleted@test.com");

        // Assert
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("USER_DELETED")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogAsync_LogsTargetEmailAsNA_WhenNull()
    {
        // Act
        await _service.LogAsync("SYSTEM_ACTION", "system", "system@internal");

        // Assert - The log message should contain "N/A" for target email
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("N/A")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogAsync_HandlesMultipleLogs()
    {
        // Act
        await _service.LogAsync("ACTION_1", "user-1", "user1@test.com");
        await _service.LogAsync("ACTION_2", "user-2", "user2@test.com");
        await _service.LogAsync("ACTION_3", "user-3", "user3@test.com");

        // Assert
        var logs = await _context.AuditLogs.ToListAsync();
        logs.Should().HaveCount(3);
        logs.Should().Contain(l => l.Action == "ACTION_1");
        logs.Should().Contain(l => l.Action == "ACTION_2");
        logs.Should().Contain(l => l.Action == "ACTION_3");
    }

    [Fact]
    public async Task LogAsync_AssignsSequentialIds()
    {
        // Act
        await _service.LogAsync("ACTION_1", "user-1", "user@test.com");
        await _service.LogAsync("ACTION_2", "user-1", "user@test.com");

        // Assert
        var logs = await _context.AuditLogs.OrderBy(l => l.Id).ToListAsync();
        logs[1].Id.Should().BeGreaterThan(logs[0].Id);
    }

    [Fact]
    public async Task LogAsync_CatchesAndLogsExceptions()
    {
        // Arrange - Use a disposed context to trigger an exception
        var disposedContext = new ApplicationDbContext(
            new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options);
        disposedContext.Dispose();

        var serviceWithDisposedContext = new AuditService(disposedContext, _loggerMock.Object);

        // Act - Should not throw
        await serviceWithDisposedContext.LogAsync("TEST", "user", "user@test.com");

        // Assert - Error should be logged
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to save audit log")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Theory]
    [InlineData("USER_LOGIN")]
    [InlineData("USER_LOGOUT")]
    [InlineData("PASSWORD_CHANGED")]
    [InlineData("ROLE_CHANGED")]
    [InlineData("USER_SUSPENDED")]
    [InlineData("TOKEN_REVOKED")]
    public async Task LogAsync_HandlesVariousActionTypes(string action)
    {
        // Act
        await _service.LogAsync(action, "admin-1", "admin@test.com");

        // Assert
        var log = await _context.AuditLogs.SingleAsync();
        log.Action.Should().Be(action);
    }

    [Fact]
    public async Task LogAsync_HandlesLongDetails()
    {
        // Arrange
        var longDetails = new string('x', 5000);

        // Act
        await _service.LogAsync("TEST", "user-1", "user@test.com", details: longDetails);

        // Assert
        var log = await _context.AuditLogs.SingleAsync();
        log.Details.Should().Be(longDetails);
    }

    [Fact]
    public async Task LogAsync_HandlesSpecialCharactersInDetails()
    {
        // Arrange
        var details = "User <script>alert('xss')</script> created with email test@test.com";

        // Act
        await _service.LogAsync("TEST", "user-1", "user@test.com", details: details);

        // Assert
        var log = await _context.AuditLogs.SingleAsync();
        log.Details.Should().Be(details);
    }

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.1")]
    [InlineData("::1")]
    [InlineData("2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
    public async Task LogAsync_HandlesVariousIPAddressFormats(string ipAddress)
    {
        // Act
        await _service.LogAsync("TEST", "user-1", "user@test.com", ipAddress: ipAddress);

        // Assert
        var log = await _context.AuditLogs.SingleAsync();
        log.IpAddress.Should().Be(ipAddress);
    }
}
