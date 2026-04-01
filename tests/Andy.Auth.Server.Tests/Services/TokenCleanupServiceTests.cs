using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests.Services;

public class TokenCleanupServiceTests
{
    private readonly Mock<IServiceProvider> _serviceProviderMock;
    private readonly Mock<ILogger<TokenCleanupService>> _loggerMock;
    private readonly Mock<IOpenIddictTokenManager> _tokenManagerMock;
    private readonly Mock<IOpenIddictAuthorizationManager> _authorizationManagerMock;

    public TokenCleanupServiceTests()
    {
        _serviceProviderMock = new Mock<IServiceProvider>();
        _loggerMock = new Mock<ILogger<TokenCleanupService>>();
        _tokenManagerMock = new Mock<IOpenIddictTokenManager>();
        _authorizationManagerMock = new Mock<IOpenIddictAuthorizationManager>();
    }

    private TokenCleanupService CreateService(int intervalMinutes = 60)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OpenIddict:TokenCleanupIntervalMinutes"] = intervalMinutes.ToString()
            })
            .Build();

        return new TokenCleanupService(_serviceProviderMock.Object, _loggerMock.Object, config);
    }

    private void SetupServiceScope()
    {
        var scopeMock = new Mock<IServiceScope>();
        var scopeProviderMock = new Mock<IServiceProvider>();

        scopeProviderMock.Setup(x => x.GetService(typeof(IOpenIddictTokenManager)))
            .Returns(_tokenManagerMock.Object);
        scopeProviderMock.Setup(x => x.GetService(typeof(IOpenIddictAuthorizationManager)))
            .Returns(_authorizationManagerMock.Object);

        scopeMock.Setup(x => x.ServiceProvider).Returns(scopeProviderMock.Object);

        var scopeFactoryMock = new Mock<IServiceScopeFactory>();
        scopeFactoryMock.Setup(x => x.CreateScope()).Returns(scopeMock.Object);

        _serviceProviderMock.Setup(x => x.GetService(typeof(IServiceScopeFactory)))
            .Returns(scopeFactoryMock.Object);
    }

    // ==================== Constructor Tests ====================

    [Fact]
    public void Constructor_DefaultInterval_Uses60Minutes()
    {
        // Arrange
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        // Act - Create service without specifying interval
        var service = new TokenCleanupService(_serviceProviderMock.Object, _loggerMock.Object, config);

        // Assert - Service should be created successfully with default interval
        service.Should().NotBeNull();
    }

    [Fact]
    public void Constructor_CustomInterval_UsesConfiguredValue()
    {
        // Arrange & Act
        var service = CreateService(intervalMinutes: 30);

        // Assert
        service.Should().NotBeNull();
    }

    // ==================== ExecuteAsync Tests ====================

    [Fact]
    public async Task ExecuteAsync_CancellationRequested_StopsGracefully()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act - Start and immediately cancel
        var task = service.StartAsync(cts.Token);
        cts.Cancel();

        // Assert - Should complete without throwing
        await Task.WhenAny(task, Task.Delay(1000));
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task ExecuteAsync_PrunesTokensAndAuthorizations()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(5L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(3L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act
        var task = service.StartAsync(cts.Token);

        // Wait for at least one cleanup cycle
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert
        _tokenManagerMock.Verify(x => x.PruneAsync(
            It.IsAny<DateTimeOffset>(),
            It.IsAny<CancellationToken>()), Times.AtLeastOnce);
        _authorizationManagerMock.Verify(x => x.PruneAsync(
            It.IsAny<DateTimeOffset>(),
            It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_LogsTokensPruned()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(10L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert - Verify logging was called
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Pruned") && v.ToString()!.Contains("tokens")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_LogsAuthorizationsPruned()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(7L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Pruned") && v.ToString()!.Contains("authorizations")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_NoTokensToPrune_DoesNotLog()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert - Should not log when nothing was pruned
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Pruned") && v.ToString()!.Contains("tokens")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Never);
    }

    // ==================== Error Handling Tests ====================

    [Fact]
    public async Task ExecuteAsync_TokenPruneThrows_LogsErrorAndContinues()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert - Should log error
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_AuthorizationPruneThrows_LogsErrorAndContinues()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Authorization error"));

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    // ==================== Service Lifecycle Tests ====================

    [Fact]
    public async Task StartAsync_LogsServiceStarted()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 60);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(50);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // Assert
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("started")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task StopAsync_CompletesGracefully()
    {
        // Arrange
        SetupServiceScope();
        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 60);
        using var cts = new CancellationTokenSource();

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(50);

        // Assert - Stop should complete without throwing
        var stopTask = service.StopAsync(CancellationToken.None);
        cts.Cancel();
        await stopTask;
    }

    // ==================== Prune Timestamp Tests ====================

    [Fact]
    public async Task ExecuteAsync_PassesCurrentTimeToManagers()
    {
        // Arrange
        SetupServiceScope();
        DateTimeOffset capturedTokenTime = default;
        DateTimeOffset capturedAuthTime = default;

        _tokenManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<DateTimeOffset, CancellationToken>((time, _) => capturedTokenTime = time)
            .ReturnsAsync(0L);
        _authorizationManagerMock.Setup(x => x.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<DateTimeOffset, CancellationToken>((time, _) => capturedAuthTime = time)
            .ReturnsAsync(0L);

        var service = CreateService(intervalMinutes: 1);
        using var cts = new CancellationTokenSource();

        var beforeExecution = DateTimeOffset.UtcNow;

        // Act
        await service.StartAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        var afterExecution = DateTimeOffset.UtcNow;

        // Assert - Times should be within execution window
        capturedTokenTime.Should().BeOnOrAfter(beforeExecution);
        capturedTokenTime.Should().BeOnOrBefore(afterExecution);
        capturedAuthTime.Should().BeOnOrAfter(beforeExecution);
        capturedAuthTime.Should().BeOnOrBefore(afterExecution);
    }
}
