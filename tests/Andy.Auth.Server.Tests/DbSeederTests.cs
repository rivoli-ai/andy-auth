using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Tests for the DbSeeder class
/// </summary>
public class DbSeederTests : IDisposable
{
    // Admin password env vars exposed by DbSeeder.SeedTestUserAsync. Outside
    // Development the seeder throws when any of these is missing (#48), so
    // every Production-flavoured test in this file must arrange them up
    // front. We populate process env in the ctor and clear in Dispose so
    // tests stay hermetic.
    private static readonly string[] AdminPasswordEnvVars =
    {
        "ADMIN_PASSWORD_SAM",
        "ADMIN_PASSWORD_TY",
        "ADMIN_PASSWORD_DEFAULT",
    };

    private readonly Mock<IOpenIddictApplicationManager> _mockAppManager;
    private readonly Mock<IOpenIddictScopeManager> _mockScopeManager;
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<RoleManager<IdentityRole>> _mockRoleManager;
    private readonly Mock<ILogger<DbSeeder>> _mockLogger;
    private readonly IServiceProvider _serviceProvider;

    public DbSeederTests()
    {
        // Provide stable admin passwords so the Production-env tests below
        // don't trip the #48 "no admin password configured" guard.
        foreach (var envVar in AdminPasswordEnvVars)
        {
            Environment.SetEnvironmentVariable(envVar, "TestAdminPassword!23");
        }

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
        // AddLogging registers the default logger factory + ILogger<T> for any T,
        // including ILogger<RegistrationManifestLoader> which DbSeeder.SeedFromManifestsAsync
        // resolves via _serviceProvider.GetRequiredService. Without this, every test in
        // this file fails with "No service for type ILogger<RegistrationManifestLoader>"
        // (pre-existing breakage on main; fixed as part of E0-S6).
        services.AddLogging();
        services.AddSingleton(_mockAppManager.Object);
        services.AddSingleton(_mockScopeManager.Object);
        services.AddSingleton(_mockUserManager.Object);
        services.AddSingleton(_mockRoleManager.Object);
        _serviceProvider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        foreach (var envVar in AdminPasswordEnvVars)
        {
            Environment.SetEnvironmentVariable(envVar, null);
        }
    }

    [Fact]
    public async Task SeedAsync_SeedsHardcodedClients_WhenClientsDoNotExist()
    {
        // Arrange - no client exists yet, and no registration manifests are
        // configured, so the legacy hardcoded SeedClientsAsync path is what
        // runs here. andy-docs-api is deliberately NOT asserted: it moved to
        // the manifest-driven SeedFromManifestsAsync path (see the
        // `// andy-docs-api: now manifest-driven` comment in DbSeeder), so it
        // is never created by the hardcoded path a manifest-less run exercises.
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        // Act
        await seeder.SeedAsync();

        // Assert - behaviour, by client id (not a brittle total count).
        var createdIds = capturedDescriptors.Select(d => d.ClientId).ToList();
        Assert.Contains("claude-desktop", createdIds);
        Assert.Contains("andy-docs-web", createdIds);
        Assert.Contains("chatgpt", createdIds);
        Assert.Contains("cline", createdIds);
        Assert.Contains("continue-dev", createdIds);
        // andy-docs-api is manifest-driven; a manifest-less run must not
        // recreate it via the hardcoded path.
        Assert.DoesNotContain("andy-docs-api", createdIds);
    }

    [Fact]
    public async Task SeedAsync_RecreatesHardcodedClients_WhenClientsAlreadyExist()
    {
        // Arrange - every client already exists. The hardcoded clients use a
        // delete-then-create strategy on every run so config/manifest edits
        // take effect, so an existing row is deleted and the client recreated.
        var existingClient = new object();
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(existingClient);

        var createdIds = new List<string?>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => createdIds.Add(desc.ClientId))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        // Act
        await seeder.SeedAsync();

        // Assert - the pre-existing row was deleted, and representative
        // always-recreated clients were re-created.
        _mockAppManager.Verify(m => m.DeleteAsync(existingClient, default), Times.AtLeastOnce);
        Assert.Contains("claude-desktop", createdIds);
        Assert.Contains("andy-docs-web", createdIds);
    }

    [Fact]
    public async Task SeedAsync_CreatesAndyDocsApiClient_FromManifest()
    {
        // andy-docs-api moved off the hardcoded path to the manifest-driven
        // SeedFromManifestsAsync path. This asserts the CURRENT behaviour:
        // supplied a registration manifest, the seeder emits the andy-docs-api
        // descriptor (Development fallback secret, grant permissions).
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("andy-docs", new
        {
            service = new
            {
                name = "andy-docs",
                displayName = "Andy Docs",
                description = "manifest-driven andy-docs-api registration",
                embeddedProxyPrefix = "/docs"
            },
            auth = new
            {
                audience = "urn:andy-docs-api",
                apiClient = new
                {
                    clientId = "andy-docs-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "ANDY_DOCS_API_SECRET_UNSET",
                    displayName = "Andy Docs API",
                    grantTypes = new[] { "authorization_code", "refresh_token", "client_credentials" },
                    scopes = new[] { "scp:urn:andy-docs-api" }
                }
            }
        });
        Environment.SetEnvironmentVariable("ANDY_DOCS_API_SECRET_UNSET", null);

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);
        _mockScopeManager.Setup(m => m.FindByNameAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);
        _mockScopeManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictScopeDescriptor>(), default))
            .ReturnsAsync(new object());
        _mockUserManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Development" },
            { "Registrations:ManifestPaths:0", manifestDir.Path }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Development"));

        // Act
        await seeder.SeedAsync();

        // Assert - the manifest-driven andy-docs-api descriptor.
        var andyDocsDescriptor = capturedDescriptors.FirstOrDefault(d => d.ClientId == "andy-docs-api");
        Assert.NotNull(andyDocsDescriptor);
        Assert.Equal("Andy Docs API", andyDocsDescriptor!.DisplayName);
        // Confidential client, secret env var intentionally unset → the
        // Development-only deterministic fallback.
        Assert.Equal("andy-docs-api-secret-change-in-production", andyDocsDescriptor.ClientSecret);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, andyDocsDescriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken, andyDocsDescriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials, andyDocsDescriptor.Permissions);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateAndyDocsWebClient_AsPublicClient()
    {
        // Arrange - andy-docs-web doesn't exist, all others exist
        _mockAppManager.Setup(m => m.FindByClientIdAsync("andy-docs-web", default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.Is<string>(s => s != "andy-docs-web"), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Production");

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        // Act
        await seeder.SeedAsync();

        // Assert - find the andy-docs-web descriptor among all created
        var andyDocsWebDescriptor = capturedDescriptors.FirstOrDefault(d => d.ClientId == "andy-docs-web");
        Assert.NotNull(andyDocsWebDescriptor);
        Assert.Equal("Andy Docs (web)", andyDocsWebDescriptor.DisplayName);
        Assert.Equal(OpenIddictConstants.ClientTypes.Public, andyDocsWebDescriptor.ClientType);
        Assert.Null(andyDocsWebDescriptor.ClientSecret); // Public client - no secret

        // Canonical port 4202 per andy-service-template/docs/ports.md (replaces legacy wagram-web's :4200)
        Assert.Contains(new Uri("http://localhost:4202/auth/callback"), andyDocsWebDescriptor.RedirectUris);
        // Docker mode (offset +2000)
        Assert.Contains(new Uri("http://localhost:6202/auth/callback"), andyDocsWebDescriptor.RedirectUris);
        // Conductor embedded (unified proxy on 9100, /docs prefix)
        Assert.Contains(new Uri("http://localhost:9100/docs/auth/callback"), andyDocsWebDescriptor.RedirectUris);
        // UAT
        Assert.Contains(new Uri("https://docs.uat.wagram.ai/auth/callback"), andyDocsWebDescriptor.RedirectUris);
        // Production
        Assert.Contains(new Uri("https://docs.wagram.ai/auth/callback"), andyDocsWebDescriptor.RedirectUris);

        // PKCE required for this public client (closes part of andy-auth#46 for andy-docs-web).
        Assert.Contains(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange, andyDocsWebDescriptor.Requirements);
    }

    [Fact]
    public async Task SeedAsync_ShouldDeleteLegacyWagramWebClient_WhenPresent()
    {
        // Arrange - simulate a legacy DB where the old `wagram-web` row exists
        var legacyWagramRow = new object();
        var existingAndyDocsWebRow = new object();
        _mockAppManager.Setup(m => m.FindByClientIdAsync("wagram-web", default))
            .ReturnsAsync(legacyWagramRow);
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.Is<string>(s => s != "wagram-web"), default))
            .ReturnsAsync(existingAndyDocsWebRow);

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        // Act
        await seeder.SeedAsync();

        // Assert - the legacy `wagram-web` row was deleted as part of the seed
        _mockAppManager.Verify(m => m.DeleteAsync(legacyWagramRow, default), Times.Once);
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

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

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
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);

        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), "Test123!"))
            .ReturnsAsync(IdentityResult.Success);

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Development"));

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u =>
                u.Id == DbSeeder.TestUserWellKnownId && // #56 — deterministic Id for downstream pre-binding
                u.Email == "test@andy.local" &&
                u.UserName == "test@andy.local" &&
                u.EmailConfirmed == true &&
                u.FullName == "Test User" &&
                u.IsActive == true),
            "Test123!"),
            Times.Once);
    }

    [Fact]
    public async Task SeedAsync_ShouldCreateViewerTestUser_InDevelopmentEnvironment()
    {
        // Arrange — companion to SeedAsync_ShouldCreateTestUser_InDevelopmentEnvironment;
        // viewer@andy.local is the no-special-permissions counterpart to test@andy.local,
        // used by consumer E2E tests (rivoli-ai/andy-policies#109) that need an
        // authenticated-but-unauthorized identity for 403 assertions.
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Development");

        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);

        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), "Test123!"))
            .ReturnsAsync(IdentityResult.Success);

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Development"));

        // Act
        await seeder.SeedAsync();

        // Assert
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u =>
                u.Id == DbSeeder.ViewerUserWellKnownId &&
                u.Email == "viewer@andy.local" &&
                u.UserName == "viewer@andy.local" &&
                u.EmailConfirmed == true &&
                u.FullName == "Viewer User" &&
                u.IsActive == true),
            "Test123!"),
            Times.Once);
    }

    [Fact]
    public void TestUserWellKnownId_IsTheDocumentedConstant()
    {
        // Locks the Id contract so changing it requires a deliberate update —
        // downstream consumers (andy-rbac, andy-policies E2E) hardcode the same
        // string and would silently miss bindings if it drifted.
        Assert.Equal("00000000-0000-0000-0000-000000000001", DbSeeder.TestUserWellKnownId);
    }

    [Fact]
    public void ViewerUserWellKnownId_IsTheDocumentedConstant()
    {
        // Same contract lock as TestUserWellKnownId — andy-policies E2E #109
        // hardcodes this string for its 403 assertion.
        Assert.Equal("00000000-0000-0000-0000-000000000002", DbSeeder.ViewerUserWellKnownId);
    }

    [Fact]
    public async Task SeedAsync_ShouldNotCreateTestUser_InProductionEnvironment()
    {
        // Arrange
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object()); // Clients already exist

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

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
        var existingViewer = new ApplicationUser { Email = "viewer@andy.local", AccessFailedCount = 0 };
        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync(existingUser);
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync(existingViewer);

        // Mock password reset methods (DbSeeder resets test user password on startup)
        _mockUserManager.Setup(m => m.GeneratePasswordResetTokenAsync(existingUser))
            .ReturnsAsync("reset-token");
        _mockUserManager.Setup(m => m.ResetPasswordAsync(existingUser, "reset-token", "Test123!"))
            .ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.GeneratePasswordResetTokenAsync(existingViewer))
            .ReturnsAsync("viewer-reset-token");
        _mockUserManager.Setup(m => m.ResetPasswordAsync(existingViewer, "viewer-reset-token", "Test123!"))
            .ReturnsAsync(IdentityResult.Success);

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Development"));

        // Act
        await seeder.SeedAsync();

        // Assert - neither test user should be created since they already exist
        // Note: Admin users (sam@rivoli.ai, ty@rivoli.ai, admin@andy-auth.local) are still created
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local"),
            It.IsAny<string>()), Times.Never);
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "viewer@andy.local"),
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
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);

        var error = new IdentityError { Description = "Password too weak" };
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), "Test123!"))
            .ReturnsAsync(IdentityResult.Failed(error));

        var seeder = new DbSeeder(_serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Development"));

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

    #region Issue #48 — Admin password CSPRNG + no plaintext logging

    [Fact]
    public void GenerateRandomPassword_IsSixteenCharsAndCoversEveryRequiredClass()
    {
        // Regression for andy-auth#48. Run a few hundred iterations so a stuck
        // RNG (e.g. mis-seeded System.Random reuse) would manifest as
        // identical or class-deficient output.
        const int iterations = 500;
        var samples = new HashSet<string>(iterations);

        for (var i = 0; i < iterations; i++)
        {
            var pwd = DbSeeder.GenerateRandomPassword();

            Assert.Equal(16, pwd.Length);
            Assert.Contains(pwd, c => char.IsUpper(c));
            Assert.Contains(pwd, c => char.IsLower(c));
            Assert.Contains(pwd, c => char.IsDigit(c));
            Assert.Contains(pwd, c => "!@#$%^&*".Contains(c));

            samples.Add(pwd);
        }

        // 500 16-char passwords pulled from a 70-char alphabet collide with
        // probability ≈ 0 under a CSPRNG; the old new-Random impl could
        // collide every run. Treat any duplicate as a hard failure.
        Assert.Equal(iterations, samples.Count);
    }

    [Fact]
    public async Task SeedAsync_AdminUser_NoPasswordEnvVar_ThrowsInProduction()
    {
        // Regression for andy-auth#48. Before the fix, missing
        // ADMIN_PASSWORD_* env vars in Production caused the seeder to
        // generate a password and log it at WARN level, leaking permanent
        // admin credentials into log aggregators. The fix is to refuse to
        // start instead.
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_SAM", null);
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_TY", null);
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_DEFAULT", null);

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object()); // Clients already exist — short-circuit client seeding.

        var configuration = CreateConfiguration("Production");
        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => seeder.SeedAsync());
        // Message must name the env var so an operator can fix it.
        Assert.Contains("ADMIN_PASSWORD_", ex.Message);
        Assert.Contains("Production", ex.Message);
    }

    [Fact]
    public async Task SeedAsync_AdminUser_NoPasswordEnvVar_NeverLogsPasswordValueInDevelopment()
    {
        // Development env also exercises the test-user creation branch — wire
        // it up so the seeder doesn't NRE on a null IdentityResult.
        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local" || u.Email == "viewer@andy.local"),
            It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        // Even in Development we must not log the generated password value.
        // Pre-fix the seeder logged "Using generated password: {Password}".
        // The new log message names only the env var; this test guards
        // against accidental re-introduction of the value in the message
        // template by failing if any logged message contains the actual
        // password string.
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_SAM", null);
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_TY", null);
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_DEFAULT", null);

        var loggedMessages = new List<string>();
        var capturingLogger = new Mock<ILogger<DbSeeder>>();
        capturingLogger.Setup(x => x.Log(
            It.IsAny<LogLevel>(),
            It.IsAny<EventId>(),
            It.IsAny<It.IsAnyType>(),
            It.IsAny<Exception?>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()))
            .Callback(new InvocationAction(invocation =>
            {
                var state = invocation.Arguments[2];
                var formatter = invocation.Arguments[4];
                var message = formatter.GetType().GetMethod("Invoke")!
                    .Invoke(formatter, new[] { state, invocation.Arguments[3] }) as string;
                if (message is not null) loggedMessages.Add(message);
            }));

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Development");
        var seeder = new DbSeeder(
            _serviceProvider, configuration, capturingLogger.Object, CreateHostEnvironment("Development"));

        await seeder.SeedAsync();

        // Assert: at least one warning mentioning the env var, but none
        // contain the recognisable special-character set used in generated
        // passwords nor the literal "Using generated password: " template.
        Assert.Contains(loggedMessages, m => m.Contains("ADMIN_PASSWORD_SAM"));
        Assert.DoesNotContain(loggedMessages, m =>
            m.Contains("Using generated password:") || m.Contains("generated password: "));
    }

    [Fact]
    public async Task SeedAsync_AdminUser_NoPasswordEnvVar_DoesNotThrowInEmbedded()
    {
        // Regression for rivoli-ai/andy-auth#100. Conductor runs andy-auth with
        // ASPNETCORE_ENVIRONMENT=Embedded. Before this fix, missing
        // ADMIN_PASSWORD_* env vars made the seeder throw on the FIRST admin
        // user (sam@rivoli.ai) — aborting before SeedTestUserAsync ever reached
        // its test@andy.local / viewer@andy.local creation block. The embedded
        // auth DB then booted with roles + OIDC clients but zero users, and
        // every Conductor panel surfaced "Failed to sign in with
        // test@andy.local via TestLogin" forever. Treat Embedded like
        // Development for this carveout — symmetric with the OAuth client
        // secret seeding at DbSeeder.cs:243.
        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local" || u.Email == "viewer@andy.local"),
            It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_SAM", null);
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_TY", null);
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_DEFAULT", null);

        var loggedMessages = new List<string>();
        var capturingLogger = new Mock<ILogger<DbSeeder>>();
        capturingLogger.Setup(x => x.Log(
            It.IsAny<LogLevel>(),
            It.IsAny<EventId>(),
            It.IsAny<It.IsAnyType>(),
            It.IsAny<Exception?>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()))
            .Callback(new InvocationAction(invocation =>
            {
                var state = invocation.Arguments[2];
                var formatter = invocation.Arguments[4];
                var message = formatter.GetType().GetMethod("Invoke")!
                    .Invoke(formatter, new[] { state, invocation.Arguments[3] }) as string;
                if (message is not null) loggedMessages.Add(message);
            }));

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration("Embedded");
        var seeder = new DbSeeder(
            _serviceProvider, configuration, capturingLogger.Object, CreateHostEnvironment("Embedded"));

        // Must NOT throw — the throw was the symptom that aborted user seeding.
        await seeder.SeedAsync();

        // Test user creation must have been reached and invoked.
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local"),
            It.IsAny<string>()), Times.Once);

        // The dev-fallback warning must name the env var and the Embedded
        // environment — operators need a breadcrumb to set a stable password
        // without having to grep the source.
        Assert.Contains(loggedMessages, m => m.Contains("ADMIN_PASSWORD_SAM"));
        Assert.Contains(loggedMessages, m => m.Contains("Embedded"));
        Assert.DoesNotContain(loggedMessages, m =>
            m.Contains("Using generated password:") || m.Contains("generated password: "));
    }

    #endregion

    #region Issue #47 — Hardcoded fallback client secret regression

    [Fact]
    public async Task SeedAsync_ConfidentialClient_NoEnvVar_ThrowsInProduction()
    {
        // Regression for andy-auth#47. Before the fix, ResolveClientSecret
        // silently fell back to "<clientId>-secret-change-in-production" — a
        // well-known credential — when the configured env var was empty in
        // any environment, including Production. The fix throws outside
        // Development. This test wires a manifest with a confidential
        // apiClient whose ClientSecretEnvVar is intentionally not set in the
        // process environment, then asserts that seeding under Production
        // throws InvalidOperationException naming both the env var and the
        // client id so operators can act on the error.
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("andy-fortyseven", new
        {
            service = new
            {
                name = "andy-fortyseven",
                displayName = "Andy 47 Test",
                description = "regression manifest for andy-auth#47",
                embeddedProxyPrefix = "/fortyseven"
            },
            auth = new
            {
                audience = "urn:andy-fortyseven-api",
                apiClient = new
                {
                    clientId = "andy-fortyseven-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "ANDY_FORTYSEVEN_API_SECRET_DOES_NOT_EXIST",
                    displayName = "Andy 47 API",
                    grantTypes = new[] { "client_credentials" },
                    scopes = new[] { "openid" }
                }
            }
        });

        // Belt-and-braces: ensure the env var really is unset.
        Environment.SetEnvironmentVariable("ANDY_FORTYSEVEN_API_SECRET_DOES_NOT_EXIST", null);

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Production" },
            { "Registrations:ManifestPaths:0", manifestDir.Path }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        // Act + Assert
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => seeder.SeedAsync());
        Assert.Contains("ANDY_FORTYSEVEN_API_SECRET_DOES_NOT_EXIST", ex.Message);
        Assert.Contains("andy-fortyseven-api", ex.Message);
    }

    [Fact]
    public async Task SeedAsync_ConfidentialClient_NoEnvVar_FallsBackInDevelopment()
    {
        // Companion to the Production guard: Development must still allow the
        // deterministic fallback so contributors don't need to set env vars
        // for local-only flows. If this regresses, the guard would lock
        // Development out too.
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("andy-fortyseven-dev", new
        {
            service = new
            {
                name = "andy-fortyseven-dev",
                displayName = "Andy 47 Dev Test",
                description = "regression manifest for andy-auth#47 dev path",
                embeddedProxyPrefix = "/fortysevendev"
            },
            auth = new
            {
                audience = "urn:andy-fortyseven-dev-api",
                apiClient = new
                {
                    clientId = "andy-fortyseven-dev-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "ANDY_FORTYSEVEN_DEV_SECRET_UNSET",
                    displayName = "Andy 47 Dev API",
                    grantTypes = new[] { "client_credentials" },
                    scopes = new[] { "openid" }
                }
            }
        });
        Environment.SetEnvironmentVariable("ANDY_FORTYSEVEN_DEV_SECRET_UNSET", null);

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .ReturnsAsync(new object());
        _mockScopeManager.Setup(m => m.FindByNameAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);
        _mockScopeManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictScopeDescriptor>(), default))
            .ReturnsAsync(new object());
        _mockUserManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Development" },
            { "Registrations:ManifestPaths:0", manifestDir.Path }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Development"));

        // Should not throw; assert the descriptor went out with the dev
        // fallback secret.
        await seeder.SeedAsync();

        _mockAppManager.Verify(m => m.CreateAsync(
            It.Is<OpenIddictApplicationDescriptor>(d =>
                d.ClientId == "andy-fortyseven-dev-api"
                && d.ClientSecret == "andy-fortyseven-dev-api-secret-change-in-production"),
            default),
            Times.Once);
    }

    [Fact]
    public async Task SeedAsync_TokenExchangeActor_GetsResourcePermissionForEachAudience()
    {
        // Regression for rivoli-ai/conductor#943. OpenIddict rejects token-
        // exchange requests carrying a `resource` parameter with
        // ID2192 ("This client application is not allowed to use the
        // specified resource(s)") unless the client has a per-resource
        // permission (`rsr:<audience>`) seeded. The seeder used to add the
        // token-exchange grant-type permission but never the matching
        // resource permissions — the symptom was every container create
        // returning HTTP 500 with the andy-models OBO exchange failing at
        // the andy-auth token endpoint with HTTP 400.
        //
        // This test wires a manifest with a token-exchange-capable client
        // and two TokenExchange:Policies entries naming that client as
        // ActorClientId, then asserts both resource permissions land on
        // the captured descriptor.
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("actor", new
        {
            service = new
            {
                name = "actor-service",
                displayName = "Actor Service",
                description = "regression manifest for conductor#943",
                embeddedProxyPrefix = "/actor"
            },
            auth = new
            {
                audience = "urn:actor-api",
                apiClient = new
                {
                    clientId = "actor-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "ACTOR_API_SECRET",
                    displayName = "Actor API",
                    grantTypes = new[] { "client_credentials", "token_exchange" },
                    scopes = new[] { "openid" }
                }
            }
        });
        Environment.SetEnvironmentVariable("ACTOR_API_SECRET", "test-secret");

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Production" },
            { "Registrations:ManifestPaths:0", manifestDir.Path },
            { "TokenExchange:Policies:0:ActorClientId", "actor-api" },
            { "TokenExchange:Policies:0:Audience", "urn:downstream-one-api" },
            { "TokenExchange:Policies:1:ActorClientId", "actor-api" },
            { "TokenExchange:Policies:1:Audience", "urn:downstream-two-api" },
            // Decoy: a policy for a different actor must NOT leak resource
            // permissions onto our client.
            { "TokenExchange:Policies:2:ActorClientId", "some-other-api" },
            { "TokenExchange:Policies:2:Audience", "urn:should-not-leak-api" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        await seeder.SeedAsync();

        var actor = capturedDescriptors.FirstOrDefault(d => d.ClientId == "actor-api");
        Assert.NotNull(actor);
        Assert.Contains(
            OpenIddictConstants.Permissions.Prefixes.GrantType + Andy.Auth.Server.Services.TokenExchangeConstants.GrantType,
            actor!.Permissions);
        Assert.Contains(
            OpenIddictConstants.Permissions.Prefixes.Resource + "urn:downstream-one-api",
            actor.Permissions);
        Assert.Contains(
            OpenIddictConstants.Permissions.Prefixes.Resource + "urn:downstream-two-api",
            actor.Permissions);
        Assert.DoesNotContain(
            OpenIddictConstants.Permissions.Prefixes.Resource + "urn:should-not-leak-api",
            actor.Permissions);

        Environment.SetEnvironmentVariable("ACTOR_API_SECRET", null);
    }

    [Fact]
    public async Task SeedAsync_NonTokenExchangeClient_DoesNotGetResourcePermissions()
    {
        // Companion to the test above: a client that doesn't declare
        // token_exchange in its grantTypes must not get `rsr:` permissions
        // even if a (mis-configured) TokenExchange:Policies entry names it
        // as ActorClientId. OpenIddict's resource enforcement only kicks
        // in for requests that carry a `resource` parameter, and we want
        // to keep the principle of least privilege: no token-exchange
        // grant => no resource permissions.
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("plain", new
        {
            service = new
            {
                name = "plain-service",
                displayName = "Plain Service",
                description = "plain client_credentials, no token_exchange",
                embeddedProxyPrefix = "/plain"
            },
            auth = new
            {
                audience = "urn:plain-api",
                apiClient = new
                {
                    clientId = "plain-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "PLAIN_API_SECRET",
                    displayName = "Plain API",
                    grantTypes = new[] { "client_credentials" },
                    scopes = new[] { "openid" }
                }
            }
        });
        Environment.SetEnvironmentVariable("PLAIN_API_SECRET", "test-secret");

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var capturedDescriptors = new List<OpenIddictApplicationDescriptor>();
        _mockAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), default))
            .Callback<OpenIddictApplicationDescriptor, CancellationToken>((desc, _) => capturedDescriptors.Add(desc))
            .ReturnsAsync(new object());

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Production" },
            { "Registrations:ManifestPaths:0", manifestDir.Path },
            { "TokenExchange:Policies:0:ActorClientId", "plain-api" },
            { "TokenExchange:Policies:0:Audience", "urn:must-not-appear-api" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        await seeder.SeedAsync();

        var plain = capturedDescriptors.FirstOrDefault(d => d.ClientId == "plain-api");
        Assert.NotNull(plain);
        Assert.DoesNotContain(
            OpenIddictConstants.Permissions.Prefixes.Resource + "urn:must-not-appear-api",
            plain!.Permissions);
        Assert.DoesNotContain(
            OpenIddictConstants.Permissions.Prefixes.GrantType + Andy.Auth.Server.Services.TokenExchangeConstants.GrantType,
            plain.Permissions);

        Environment.SetEnvironmentVariable("PLAIN_API_SECRET", null);
    }

    [Fact]
    public async Task SeedAsync_ManifestScope_IncludesApiClientIdResource_OnCreate()
    {
        // Regression for the OBO exchange ID2187 failure. OpenIddict only
        // lets a client exchange a subject token (RFC 8693) when the token
        // names that CLIENT among its audiences or presenters. User tokens
        // get their `aud` from the scope's Resources, which used to contain
        // only the audience URN (`urn:<svc>-api`) — never the api client id
        // (`<svc>-api`) — so every service-initiated OBO exchange died with
        // "The specified subject token cannot be used by this client
        // application" and fell back to a mislabelled M2M identity.
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("obo", new
        {
            service = new
            {
                name = "obo-service",
                displayName = "OBO Service",
                description = "regression manifest for the ID2187 OBO failure",
                embeddedProxyPrefix = "/obo"
            },
            auth = new
            {
                audience = "urn:obo-api",
                apiClient = new
                {
                    clientId = "obo-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "OBO_API_SECRET",
                    displayName = "OBO API",
                    grantTypes = new[] { "client_credentials" },
                    scopes = new[] { "openid" }
                }
            }
        });
        Environment.SetEnvironmentVariable("OBO_API_SECRET", "test-secret");

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);
        _mockScopeManager.Setup(m => m.FindByNameAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var capturedScopes = new List<OpenIddictScopeDescriptor>();
        _mockScopeManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictScopeDescriptor>(), default))
            .Callback<OpenIddictScopeDescriptor, CancellationToken>((desc, _) => capturedScopes.Add(desc))
            .ReturnsAsync(new object());

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Production" },
            { "Registrations:ManifestPaths:0", manifestDir.Path }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        await seeder.SeedAsync();

        var scope = capturedScopes.FirstOrDefault(d => d.Name == "urn:obo-api");
        Assert.NotNull(scope);
        Assert.Contains("urn:obo-api", scope!.Resources);
        Assert.Contains("obo-api", scope.Resources);

        Environment.SetEnvironmentVariable("OBO_API_SECRET", null);
    }

    [Fact]
    public async Task SeedAsync_ManifestScope_AddsMissingClientIdResource_OnExistingScope()
    {
        // Companion to the create-path test: already-seeded databases must be
        // reconciled. The old seeder early-returned when the scope existed, so
        // a deployed environment could never pick up new scope resources
        // without dropping the auth database. The seeder now compares the
        // existing scope's resources against the manifest-derived set and
        // updates when anything is missing.
        using var manifestDir = new TempManifestDirectory();
        manifestDir.WriteManifest("obo-existing", new
        {
            service = new
            {
                name = "obo-existing-service",
                displayName = "OBO Existing Service",
                description = "update-path regression for the ID2187 OBO failure",
                embeddedProxyPrefix = "/obo-existing"
            },
            auth = new
            {
                audience = "urn:obo-existing-api",
                apiClient = new
                {
                    clientId = "obo-existing-api",
                    clientType = "confidential",
                    clientSecretEnvVar = "OBO_EXISTING_API_SECRET",
                    displayName = "OBO Existing API",
                    grantTypes = new[] { "client_credentials" },
                    scopes = new[] { "openid" }
                }
            }
        });
        Environment.SetEnvironmentVariable("OBO_EXISTING_API_SECRET", "test-secret");

        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync((object?)null);

        var existingScope = new object();
        _mockScopeManager.Setup(m => m.FindByNameAsync("urn:obo-existing-api", default))
            .ReturnsAsync(existingScope);
        // Existing scope has only the audience URN — the pre-fix state.
        _mockScopeManager.Setup(m => m.GetResourcesAsync(existingScope, default))
            .ReturnsAsync(System.Collections.Immutable.ImmutableArray.Create("urn:obo-existing-api"));
        _mockScopeManager.Setup(m => m.PopulateAsync(It.IsAny<OpenIddictScopeDescriptor>(), existingScope, default))
            .Callback<OpenIddictScopeDescriptor, object, CancellationToken>((desc, _, _) =>
            {
                desc.Name = "urn:obo-existing-api";
                desc.Resources.Add("urn:obo-existing-api");
            })
            .Returns(ValueTask.CompletedTask);

        OpenIddictScopeDescriptor? updatedDescriptor = null;
        _mockScopeManager.Setup(m => m.UpdateAsync(existingScope, It.IsAny<OpenIddictScopeDescriptor>(), default))
            .Callback<object, OpenIddictScopeDescriptor, CancellationToken>((_, desc, _) => updatedDescriptor = desc)
            .Returns(ValueTask.CompletedTask);

        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", "Production" },
            { "Registrations:ManifestPaths:0", manifestDir.Path }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("Production"));

        await seeder.SeedAsync();

        Assert.NotNull(updatedDescriptor);
        Assert.Contains("urn:obo-existing-api", updatedDescriptor!.Resources);
        Assert.Contains("obo-existing-api", updatedDescriptor.Resources);

        Environment.SetEnvironmentVariable("OBO_EXISTING_API_SECRET", null);
    }

    /// <summary>
    /// Disposable temp directory holding one or more registration.json
    /// manifest files. Wired into config via "Registrations:ManifestPaths".
    /// </summary>
    private sealed class TempManifestDirectory : IDisposable
    {
        public string Path { get; }

        public TempManifestDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "andy-auth-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public void WriteManifest(string name, object manifest)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(
                manifest,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(System.IO.Path.Combine(Path, name + ".json"), json);
        }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch { /* best-effort */ }
        }
    }

    #endregion

    /// <summary>
    /// Helper method to create a real IConfiguration instance
    /// </summary>
    private static IConfiguration CreateConfiguration(
        string environment, params (string Key, string Value)[] extra)
    {
        var configValues = new Dictionary<string, string?>
        {
            { "ASPNETCORE_ENVIRONMENT", environment }
        };

        foreach (var (key, value) in extra)
        {
            configValues[key] = value;
        }

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();
    }

    /// <summary>
    /// Helper to construct an <see cref="IHostEnvironment"/> with the given
    /// environment name. DbSeeder uses this for the "is this Production?"
    /// guards in <c>ResolveClientSecret</c> (#47) and admin-password handling
    /// (#48), so tests must set it explicitly.
    /// </summary>
    private static IHostEnvironment CreateHostEnvironment(string environmentName)
    {
        return new TestHostEnvironment
        {
            EnvironmentName = environmentName,
            ApplicationName = "Andy.Auth.Server.Tests",
            ContentRootPath = AppContext.BaseDirectory,
            ContentRootFileProvider = new Microsoft.Extensions.FileProviders.NullFileProvider()
        };
    }

    /// <summary>
    /// Minimal IHostEnvironment stub. The framework's HostingEnvironment type
    /// lives in Microsoft.Extensions.Hosting.Internal which is not part of the
    /// public API surface, so tests roll their own.
    /// </summary>
    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = string.Empty;
        public string ApplicationName { get; set; } = string.Empty;
        public string ContentRootPath { get; set; } = string.Empty;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; }
            = new Microsoft.Extensions.FileProviders.NullFileProvider();
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

    // ==================== andy-auth#54: test-user seeding scope ====================

    [Theory]
    [InlineData("UAT")]
    [InlineData("Staging")]
    public async Task SeedAsync_DoesNotCreateTestUsers_InInternetFacingEnvironments(string environment)
    {
        // The bug: the gate was `environment != "Production"`, so UAT and
        // Staging seeded test@andy.local with the published password Test123!
        // and cleared its lockout on every boot. UAT is internet-facing, which
        // made that a permanent pre-authenticated foothold no password policy
        // could close — the seeder simply put it back.
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration(environment);
        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment(environment));

        await seeder.SeedAsync();

        _mockUserManager.Verify(m => m.FindByEmailAsync("test@andy.local"), Times.Never);
        _mockUserManager.Verify(m => m.FindByEmailAsync("viewer@andy.local"), Times.Never);
        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local" || u.Email == "viewer@andy.local"),
            It.IsAny<string>()), Times.Never);
    }

    [Theory]
    [InlineData("production")]
    [InlineData("PRODUCTION")]
    public async Task SeedAsync_DoesNotCreateTestUsers_WhenEnvironmentNameCasingDiffers(string environment)
    {
        // The old check was an ordinal compare against the literal "Production",
        // so a lowercase environment name fell straight through to the seeding
        // branch. IHostEnvironment's own checks are case-insensitive.
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());

        var configuration = CreateConfiguration(environment);
        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment(environment));

        await seeder.SeedAsync();

        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local" || u.Email == "viewer@andy.local"),
            It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SeedAsync_CreatesTestUsers_WhenExplicitlyOptedIn()
    {
        // An ephemeral CI stack can still ask for them — but it has to say so,
        // rather than getting them as a side effect of its environment name.
        _mockAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new object());
        _mockUserManager.Setup(m => m.FindByEmailAsync("test@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("viewer@andy.local"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), "Test123!"))
            .ReturnsAsync(IdentityResult.Success);

        var configuration = CreateConfiguration("UAT", ("SEED_TEST_USERS", "true"));
        var seeder = new DbSeeder(
            _serviceProvider, configuration, _mockLogger.Object, CreateHostEnvironment("UAT"));

        await seeder.SeedAsync();

        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u => u.Email == "test@andy.local"),
            "Test123!"), Times.Once);
    }
}
