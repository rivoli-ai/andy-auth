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
    private readonly Mock<RoleManager<IdentityRole>> _mockRoleManager;
    private readonly Mock<ILogger<DbSeeder>> _mockLogger;
    private readonly IServiceProvider _serviceProvider;

    public DbSeederTests()
    {
        // Setup mocks
        _mockAppManager = new Mock<IOpenIddictApplicationManager>();
        _mockScopeManager = new Mock<IOpenIddictScopeManager>();
        _mockUserManager = MockUserManager();
        _mockRoleManager = MockRoleManager();
        _mockLogger = new Mock<ILogger<DbSeeder>>();

        // Setup role manager to return true for role existence checks
        _mockRoleManager.Setup(r => r.RoleExistsAsync("Admin")).ReturnsAsync(true);
        _mockRoleManager.Setup(r => r.RoleExistsAsync("User")).ReturnsAsync(true);

        // Setup admin user mocks - these are created in ALL environments now
        var adminEmails = new[] { "sam@rivoli.ai", "ty@rivoli.ai", "admin@andy-auth.local" };
        foreach (var email in adminEmails)
        {
            _mockUserManager.Setup(m => m.FindByEmailAsync(email))
                .ReturnsAsync((ApplicationUser?)null);
        }
        _mockUserManager.Setup(m => m.CreateAsync(It.Is<ApplicationUser>(u => adminEmails.Contains(u.Email!)), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Admin"))
            .ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);

        // Setup service provider
        var services = new ServiceCollection();
        services.AddSingleton(_mockAppManager.Object);
        services.AddSingleton(_mockScopeManager.Object);
        services.AddSingleton(_mockUserManager.Object);
        services.AddSingleton(_mockRoleManager.Object);
        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task SeedAsync_ShouldSeedClients_WhenClientsDoNotExist()
    {
        // Arrange - All clients don't exist
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert - 7 clients are created: lexipro-api, wagram-web, claude-desktop, chatgpt, cline, roo, continue-dev
        _mockAppManager.Verify(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default),
            Times.Exactly(7));
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

        // Assert - lexipro-api, wagram-web, claude-desktop, chatgpt, cline, roo, continue-dev are always deleted and recreated
        // So we expect 7 CreateAsync calls for the always-recreated clients
        _mockAppManager.Verify(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default),
            Times.Exactly(7));
        // And 7 DeleteAsync calls
        _mockAppManager.Verify(m => m.DeleteAsync(It.IsAny<object>(), default),
            Times.Exactly(7));
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateLexiproApiClient_WithCorrectConfiguration()
    {
        // Arrange - lexipro-api doesn't exist, all others exist
        _mockAppManager.Setup(m => m.FindByClientIdAsync("lexipro-api", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.Is<string>(s => s != "lexipro-api"), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert - find the lexipro-api descriptor among all created
        var lexiproDescriptor = capturedDescriptors.FirstOrDefault(d => d.ClientId == "lexipro-api");
        Assert.NotNull(lexiproDescriptor);
        Assert.Equal("Lexipro API", lexiproDescriptor.DisplayName);
        Assert.Equal("lexipro-secret-change-in-production", lexiproDescriptor.ClientSecret);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, lexiproDescriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken, lexiproDescriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials, lexiproDescriptor.Permissions);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateWagramWebClient_AsPublicClient()
    {
        // Arrange - wagram-web doesn't exist, all others exist
        _mockAppManager.Setup(m => m.FindByClientIdAsync("wagram-web", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.Is<string>(s => s != "wagram-web"), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert - find the wagram-web descriptor among all created
        var wagramDescriptor = capturedDescriptors.FirstOrDefault(d => d.ClientId == "wagram-web");
        Assert.NotNull(wagramDescriptor);
        Assert.Equal("Wagram Web Application", wagramDescriptor.DisplayName);
        Assert.Null(wagramDescriptor.ClientSecret); // Public client - no secret
        Assert.Contains(new Uri("https://localhost:4200/callback"), wagramDescriptor.RedirectUris);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateClaudeDesktopClient_WithHttpRedirectUris()
    {
        // Arrange - all clients exist (claude-desktop is always deleted and recreated)
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert - claude-desktop is always recreated
        var claudeDescriptor = capturedDescriptors.FirstOrDefault(d => d.ClientId == "claude-desktop");
        Assert.NotNull(claudeDescriptor);
        Assert.Null(claudeDescriptor.ClientSecret); // Public client
        Assert.Contains(new Uri("http://127.0.0.1/callback"), claudeDescriptor.RedirectUris);
        Assert.Contains(new Uri("http://localhost/callback"), claudeDescriptor.RedirectUris);
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

        // Assert - Admin users are created in all environments, but test@andy.local should NOT be created in Production
        _mockUserManager.Verify(m => m.FindByEmailAsync("test@andy.local"), Times.Never);
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local"),
            It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SeedAsync_ShouldNotCreateTestUser_WhenUserAlreadyExists()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Development");

        var existingUser = new ApplicationUser { Email = "test@andy.local", AccessFailedCount = 0 };
        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync(existingUser);

        // Mock password reset methods (DbSeeder resets test user password on startup)
        _mockUserManager.Setup(m => m.GeneratePasswordResetTokenAsync(existingUser))
            .ReturnsAsync("reset-token");
        _mockUserManager.Setup(m => m.ResetPasswordAsync(existingUser, "reset-token", "Test123!"))
            .ReturnsAsync(IdentityResult.Success);

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object);

        // Act
        await seeder.SeedAsync();

        // Assert - test@andy.local should not be created since they already exist
        // Note: Admin users (sam@rivoli.ai, ty@rivoli.ai, admin@andy-auth.local) are still created
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local"),
            It.IsAny<string>()), Times.Never);
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

    /// <summary>
    /// Helper method to create a mock RoleManager
    /// </summary>
    private static Mock<RoleManager<IdentityRole>> MockRoleManager()
    {
        var store = new Mock<IRoleStore<IdentityRole>>();
        return new Mock<RoleManager<IdentityRole>>(
            store.Object, null, null, null, null);
    }
}
