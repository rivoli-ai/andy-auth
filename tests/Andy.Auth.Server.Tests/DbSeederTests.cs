using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Tests for the DbSeeder class
/// </summary>
public class DbSeederTests
{
    private readonly Mock<IOpenIddictApplicationManager> _mockAppManager;
    private readonly Mock<IOpenIddictScopeManager> _mockScopeManager;
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<ILogger<DbSeeder>> _mockLogger;
    private readonly IServiceProvider _serviceProvider;

    public DbSeederTests()
    {
        // Setup mocks
        _mockAppManager = new Mock<IOpenIddictApplicationManager>();
        _mockScopeManager = new Mock<IOpenIddictScopeManager>();
        _mockUserManager = MockUserManager();
        _mockLogger = new Mock<ILogger<DbSeeder>>();

        // Setup service provider
        var services = new ServiceCollection();
        services.AddSingleton(_mockAppManager.Object);
        services.AddSingleton(_mockScopeManager.Object);
        services.AddSingleton(_mockUserManager.Object);
        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task SeedAsync_ShouldSeedClients_WhenClientsDoNotExist()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync("lexipro-api", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync("wagram-web", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync("claude-desktop", default))
            .ReturnsAsync((object?)null);

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockAppManager.Verify(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default),
            Times.Exactly(3));
    }

    [Fact]
    public async Task SeedAsync_ShouldNotSeedClients_WhenClientsAlreadyExist()
    {
        // Arrange
        var existingClient = new object();
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(existingClient);

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockAppManager.Verify(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default),
            Times.Never);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateLexiproApiClient_WithCorrectConfiguration()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync("lexipro-api", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync("wagram-web", default))
            .ReturnsAsync(new object());
        _mockAppManager.Setup(m => m.FindByClientIdAsync("claude-desktop", default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");

        OpenIddictApplicationDescriptor? capturedDescriptor = null;
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptor = desc)
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        Assert.NotNull(capturedDescriptor);
        Assert.Equal("lexipro-api", capturedDescriptor.ClientId);
        Assert.Equal("Lexipro API", capturedDescriptor.DisplayName);
        Assert.Equal("lexipro-secret-change-in-production", capturedDescriptor.ClientSecret);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, capturedDescriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken, capturedDescriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials, capturedDescriptor.Permissions);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateWagramWebClient_AsPublicClient()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync("lexipro-api", default))
            .ReturnsAsync(new object());
        _mockAppManager.Setup(m => m.FindByClientIdAsync("wagram-web", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync("claude-desktop", default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");

        OpenIddictApplicationDescriptor? capturedDescriptor = null;
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptor = desc)
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        Assert.NotNull(capturedDescriptor);
        Assert.Equal("wagram-web", capturedDescriptor.ClientId);
        Assert.Equal("Wagram Web Application", capturedDescriptor.DisplayName);
        Assert.Null(capturedDescriptor.ClientSecret); // Public client - no secret
        Assert.Contains(new Uri("https://localhost:4200/callback"), capturedDescriptor.RedirectUris);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateClaudeDesktopClient_WithHttpRedirectUris()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync("lexipro-api", default))
            .ReturnsAsync(new object());
        _mockAppManager.Setup(m => m.FindByClientIdAsync("wagram-web", default))
            .ReturnsAsync(new object());
        _mockAppManager.Setup(m => m.FindByClientIdAsync("claude-desktop", default))
            .ReturnsAsync((object?)null);

        var configuration = CreateConfiguration("Production");

        OpenIddictApplicationDescriptor? capturedDescriptor = null;
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptor = desc)
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        Assert.NotNull(capturedDescriptor);
        Assert.Equal("claude-desktop", capturedDescriptor.ClientId);
        Assert.Null(capturedDescriptor.ClientSecret); // Public client
        Assert.Contains(new Uri("http://127.0.0.1/callback"), capturedDescriptor.RedirectUris);
        Assert.Contains(new Uri("http://localhost/callback"), capturedDescriptor.RedirectUris);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateTestUser_InDevelopmentEnvironment()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object()); // Clients already exist

        var configuration = CreateConfiguration("Development");

        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);

        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), "Test123!"))
            .ReturnsAsync(IdentityResult.Success);

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u =>
                u.Email == "test@andy.local" &&
                u.UserName == "test@andy.local" &&
                u.EmailConfirmed == true &&
                u.FullName == "Test User" &&
                u.IsActive == true),
            "Test123!"),
            Times.Once);
    }

    [Fact]
    public async Task SeedAsync_ShouldNotCreateTestUser_InProductionEnvironment()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object()); // Clients already exist

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockUserManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        _mockUserManager.Verify(m => m.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SeedAsync_ShouldNotCreateTestUser_WhenUserAlreadyExists()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Development");

        var existingUser = new ApplicationUser { Email = "test@andy.local" };
        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync(existingUser);

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockUserManager.Verify(m => m.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SeedAsync_ShouldLogWarning_WhenUserCreationFails()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Development");

        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);

        var error = new IdentityError { Description = "Password too weak" };
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), "Test123!"))
            .ReturnsAsync(IdentityResult.Failed(error));

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to create test user")),
                It.IsAny<Exception>(),
                It.Is<Func<It.IsAnyType, Exception?, string>>((v, t) => true)),
            Times.Once);
    }

    /// <summary>
    /// Helper method to create a real IConfiguration instance
    /// </summary>
    private static IConfiguration CreateConfiguration(string environment)
    {
        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", environment }
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();
    }

    /// <summary>
    /// Helper method to create a mock UserManager
    /// </summary>
    private static Mock<UserManager<ApplicationUser>> MockUserManager()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        return new Mock<UserManager<ApplicationUser>>(
            store.Object, null, null, null, null, null, null, null, null);
    }
}
