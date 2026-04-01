using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using System.Linq.Expressions;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore.Query;

namespace Andy.Auth.Server.Tests;

public class AdminControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<IOpenIddictApplicationManager> _applicationManagerMock;
    private readonly Mock<IOpenIddictTokenManager> _tokenManagerMock;
    private readonly Mock<IOpenIddictAuthorizationManager> _authorizationManagerMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ILogger<AdminController>> _loggerMock;
    private readonly AdminController _controller;

    public AdminControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _applicationManagerMock = new Mock<IOpenIddictApplicationManager>();
        _tokenManagerMock = new Mock<IOpenIddictTokenManager>();
        _authorizationManagerMock = new Mock<IOpenIddictAuthorizationManager>();
        _auditServiceMock = new Mock<IAuditService>();
        _loggerMock = new Mock<ILogger<AdminController>>();

        _controller = new AdminController(
            _context,
            _userManagerMock.Object,
            _applicationManagerMock.Object,
            _tokenManagerMock.Object,
            _authorizationManagerMock.Object,
            _auditServiceMock.Object,
            _loggerMock.Object);

        // Setup HttpContext with admin user
        var adminUser = new ApplicationUser { Id = "admin-1", Email = "admin@test.com", UserName = "admin@test.com" };
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "admin-1"),
            new("email", "admin@test.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext { User = principal };
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        // Setup TempData
        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());

        // Setup GetUserAsync to return admin user
        _userManagerMock.Setup(x => x.GetUserAsync(principal)).ReturnsAsync(adminUser);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== Index Tests ====================

    [Fact]
    public async Task Index_ReturnsViewWithStats()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "active@test.com", IsActive = true, LastLoginAt = DateTime.UtcNow },
            new() { Id = "user-2", Email = "inactive@test.com", IsActive = false }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _applicationManagerMock.Setup(x => x.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
            .Returns(AdminTestHelpers.EmptyAsyncEnumerable<object>());

        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        _controller.ViewBag.Stats.Should().NotBeNull();
    }

    // ==================== SuspendUser Tests ====================

    [Fact]
    public async Task SuspendUser_SuspendsUserAndRedirects()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.SuspendUser("user-1", "Policy violation");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Users");
        user.IsSuspended.Should().BeTrue();
        user.SuspensionReason.Should().Be("Policy violation");
        user.SuspendedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        _controller.TempData["SuccessMessage"].Should().NotBeNull();
    }

    [Fact]
    public async Task SuspendUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.SuspendUser("non-existent", "Test");

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    // ==================== UnsuspendUser Tests ====================

    [Fact]
    public async Task UnsuspendUser_UnsuspendsUserAndRedirects()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com",
            IsSuspended = true,
            SuspensionReason = "Old reason"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.UnsuspendUser("user-1");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Users");
        user.IsSuspended.Should().BeFalse();
        user.SuspensionReason.Should().BeNull();
    }

    [Fact]
    public async Task UnsuspendUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.UnsuspendUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    // ==================== DeleteUser Tests ====================

    [Fact]
    public async Task DeleteUser_SoftDeletesUserAndRedirects()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-2", Email = "delete@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-2")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.DeleteUser("user-2");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Users");
        user.DeletedAt.Should().NotBeNull();
        user.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.DeleteUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task DeleteUser_PreventsSystemUserDeletion()
    {
        // Arrange
        var systemUser = new ApplicationUser
        {
            Id = "system-1",
            Email = "system@test.com",
            IsSystemUser = true
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("system-1")).ReturnsAsync(systemUser);

        // Act
        var result = await _controller.DeleteUser("system-1");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("system user");
    }

    [Fact]
    public async Task DeleteUser_PreventsSelfDeletion()
    {
        // Arrange - Current user is "admin-1" from claims setup
        var currentUser = new ApplicationUser { Id = "admin-1", Email = "admin@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("admin-1")).ReturnsAsync(currentUser);

        // Act
        var result = await _controller.DeleteUser("admin-1");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("your own account");
    }

    // ==================== SetExpiration Tests ====================

    [Fact]
    public async Task SetExpiration_SetsExpirationDate()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        var expiresAt = DateTime.UtcNow.AddDays(30);
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.SetExpiration("user-1", expiresAt);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        user.ExpiresAt.Should().Be(expiresAt);
    }

    [Fact]
    public async Task SetExpiration_RemovesExpirationDate()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", ExpiresAt = DateTime.UtcNow.AddDays(10) };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.SetExpiration("user-1", null);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        user.ExpiresAt.Should().BeNull();
        ((string)_controller.TempData["SuccessMessage"]!).Should().Contain("removed");
    }

    // ==================== UpdateUserName Tests ====================

    [Fact]
    public async Task UpdateUserName_UpdatesName()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", FullName = "Old Name" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.UpdateUserName("user-1", "New Name");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        user.FullName.Should().Be("New Name");
    }

    [Fact]
    public async Task UpdateUserName_TrimsName()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.UpdateUserName("user-1", "  Trimmed Name  ");

        // Assert
        user.FullName.Should().Be("Trimmed Name");
    }

    [Fact]
    public async Task UpdateUserName_RejectsEmptyName()
    {
        // Act
        var result = await _controller.UpdateUserName("user-1", "");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("empty");
    }

    // ==================== ResetPassword Tests ====================

    [Fact]
    public async Task ResetPassword_ResetsPasswordAndSetsFlag()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.RemovePasswordAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddPasswordAsync(user, "NewPassword123!")).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.UpdateSecurityStampAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var passwordValidator = new Mock<IPasswordValidator<ApplicationUser>>();
        passwordValidator.Setup(x => x.ValidateAsync(_userManagerMock.Object, user, "NewPassword123!"))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.ResetPassword("user-1", "NewPassword123!");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        user.MustChangePassword.Should().BeTrue();
    }

    [Fact]
    public async Task ResetPassword_RejectsEmptyPassword()
    {
        // Act
        var result = await _controller.ResetPassword("user-1", "");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("empty");
    }

    // ==================== ChangeUserRole Tests ====================

    [Fact]
    public async Task ChangeUserRole_ChangesRole()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "Admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });
        _userManagerMock.Setup(x => x.RemoveFromRolesAsync(user, It.IsAny<IEnumerable<string>>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(user, "Admin")).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.ChangeUserRole("user-1", "Admin");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["SuccessMessage"].Should().NotBeNull();
        _userManagerMock.Verify(x => x.AddToRoleAsync(user, "Admin"), Times.Once);
    }

    [Fact]
    public async Task ChangeUserRole_RejectsInvalidRole()
    {
        // Act
        var result = await _controller.ChangeUserRole("user-1", "SuperAdmin");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("Invalid role");
    }

    [Fact]
    public async Task ChangeUserRole_PreventsLastAdminDemotion()
    {
        // Arrange
        var user = new ApplicationUser { Id = "admin-1", Email = "admin@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("admin-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "Admin")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.GetUsersInRoleAsync("Admin")).ReturnsAsync(new List<ApplicationUser> { user });

        // Act
        var result = await _controller.ChangeUserRole("admin-1", "User");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("last admin");
    }

    [Fact]
    public async Task ChangeUserRole_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.ChangeUserRole("non-existent", "User");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("not found");
    }

    // ==================== DeleteClient Tests ====================

    [Fact]
    public async Task DeleteClient_DeletesAndRedirects()
    {
        // Arrange
        var application = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Client");
        _applicationManagerMock.Setup(x => x.DeleteAsync(application, It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);

        // Act
        var result = await _controller.DeleteClient("test-client");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Clients");
        _controller.TempData["SuccessMessage"].Should().NotBeNull();
    }

    [Fact]
    public async Task DeleteClient_HandlesNonExistent()
    {
        // Arrange
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("non-existent", It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        // Act
        var result = await _controller.DeleteClient("non-existent");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
    }

    // ==================== RegenerateClientSecret Tests ====================

    [Fact]
    public async Task RegenerateClientSecret_RegeneratesForConfidentialClient()
    {
        // Arrange
        var application = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        _applicationManagerMock.Setup(x => x.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
        _applicationManagerMock.Setup(x => x.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);
        _applicationManagerMock.Setup(x => x.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Client");

        // Act
        var result = await _controller.RegenerateClientSecret("test-client");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["SuccessMessage"].Should().NotBeNull();
        _controller.TempData["NewClientSecret"].Should().NotBeNull();
    }

    [Fact]
    public async Task RegenerateClientSecret_RejectsPublicClient()
    {
        // Arrange
        var application = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("public-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        _applicationManagerMock.Setup(x => x.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);

        // Act
        var result = await _controller.RegenerateClientSecret("public-client");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
        ((string)_controller.TempData["ErrorMessage"]!).Should().Contain("public clients");
    }

    // ==================== RevokeToken Tests ====================

    [Fact]
    public async Task RevokeToken_RevokesAndRedirects()
    {
        // Arrange
        var token = new object();
        _tokenManagerMock.Setup(x => x.FindByIdAsync("token-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        _tokenManagerMock.Setup(x => x.GetSubjectAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync("user-1");
        _tokenManagerMock.Setup(x => x.TryRevokeAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1"))
            .ReturnsAsync(new ApplicationUser { Email = "user@test.com" });

        // Act
        var result = await _controller.RevokeToken("token-1");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Tokens");
        _controller.TempData["SuccessMessage"].Should().NotBeNull();
    }

    [Fact]
    public async Task RevokeToken_HandlesNonExistent()
    {
        // Arrange
        _tokenManagerMock.Setup(x => x.FindByIdAsync("non-existent", It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        // Act
        var result = await _controller.RevokeToken("non-existent");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
    }

    // ==================== RevokeUserTokens Tests ====================

    [Fact]
    public async Task RevokeUserTokens_RevokesAllUserTokens()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        var tokens = new List<object> { new object(), new object() };
        _tokenManagerMock.Setup(x => x.FindBySubjectAsync("user-1", It.IsAny<CancellationToken>()))
            .Returns(AdminTestHelpers.ToAsyncEnumerable(tokens));
        _tokenManagerMock.Setup(x => x.TryRevokeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.RevokeUserTokens("user-1");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        ((string)_controller.TempData["SuccessMessage"]!).Should().Contain("2 tokens");
    }

    // ==================== DCR Management Tests ====================

    [Fact]
    public async Task ApproveDcrClient_ApprovesClient()
    {
        // Arrange
        var dcr = new DynamicClientRegistration { ClientId = "dcr-client", IsApproved = false };
        _context.DynamicClientRegistrations.Add(dcr);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.ApproveDcrClient("dcr-client");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        var updated = await _context.DynamicClientRegistrations.FindAsync(dcr.Id);
        updated!.IsApproved.Should().BeTrue();
        updated.ApprovedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ApproveDcrClient_HandlesNonExistent()
    {
        // Act
        var result = await _controller.ApproveDcrClient("non-existent");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
    }

    [Fact]
    public async Task DisableDcrClient_DisablesClient()
    {
        // Arrange
        var dcr = new DynamicClientRegistration { ClientId = "dcr-client", IsDisabled = false };
        _context.DynamicClientRegistrations.Add(dcr);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.DisableDcrClient("dcr-client", "Security concern");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        var updated = await _context.DynamicClientRegistrations.FindAsync(dcr.Id);
        updated!.IsDisabled.Should().BeTrue();
        updated.DisabledReason.Should().Be("Security concern");
    }

    [Fact]
    public async Task EnableDcrClient_EnablesClient()
    {
        // Arrange
        var dcr = new DynamicClientRegistration
        {
            ClientId = "dcr-client",
            IsDisabled = true,
            DisabledReason = "Old reason"
        };
        _context.DynamicClientRegistrations.Add(dcr);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.EnableDcrClient("dcr-client");

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        var updated = await _context.DynamicClientRegistrations.FindAsync(dcr.Id);
        updated!.IsDisabled.Should().BeFalse();
        updated.DisabledReason.Should().BeNull();
    }

    // ==================== AuditLogs Tests ====================

    [Fact]
    public async Task AuditLogs_ReturnsViewWithLogs()
    {
        // Arrange
        _context.AuditLogs.Add(new AuditLog
        {
            Action = "UserCreated",
            PerformedById = "admin-1",
            PerformedByEmail = "admin@test.com",
            PerformedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.AuditLogs();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeAssignableTo<List<AuditLog>>().Subject;
        model.Should().HaveCount(1);
    }

    [Fact]
    public async Task AuditLogs_FiltersBySearch()
    {
        // Arrange
        _context.AuditLogs.Add(new AuditLog
        {
            Action = "UserCreated",
            PerformedById = "admin-1",
            PerformedByEmail = "admin@test.com",
            TargetUserEmail = "target@test.com",
            PerformedAt = DateTime.UtcNow
        });
        _context.AuditLogs.Add(new AuditLog
        {
            Action = "UserDeleted",
            PerformedById = "admin-1",
            PerformedByEmail = "admin@test.com",
            TargetUserEmail = "other@test.com",
            PerformedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.AuditLogs(search: "target");

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeAssignableTo<List<AuditLog>>().Subject;
        model.Should().HaveCount(1);
        model[0].TargetUserEmail.Should().Be("target@test.com");
    }

    [Fact]
    public async Task AuditLogs_FiltersByAction()
    {
        // Arrange
        _context.AuditLogs.Add(new AuditLog
        {
            Action = "UserCreated",
            PerformedById = "admin-1",
            PerformedByEmail = "admin@test.com",
            PerformedAt = DateTime.UtcNow
        });
        _context.AuditLogs.Add(new AuditLog
        {
            Action = "UserDeleted",
            PerformedById = "admin-1",
            PerformedByEmail = "admin@test.com",
            PerformedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.AuditLogs(actionFilter: "UserCreated");

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeAssignableTo<List<AuditLog>>().Subject;
        model.Should().HaveCount(1);
        model[0].Action.Should().Be("UserCreated");
    }
}

// Helper for admin controller tests
public static class AdminTestHelpers
{
    public static IAsyncEnumerable<T> ToAsyncEnumerable<T>(IEnumerable<T> source)
    {
        return new AsyncEnumerableWrapper<T>(source);
    }

    public static IAsyncEnumerable<T> EmptyAsyncEnumerable<T>()
    {
        return new EmptyAsyncEnumerableImpl<T>();
    }

    private class EmptyAsyncEnumerableImpl<T> : IAsyncEnumerable<T>
    {
        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
            => new EmptyAsyncEnumerator();

        private class EmptyAsyncEnumerator : IAsyncEnumerator<T>
        {
            public T Current => default!;
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
            public ValueTask<bool> MoveNextAsync() => ValueTask.FromResult(false);
        }
    }

    private class AsyncEnumerableWrapper<T> : IAsyncEnumerable<T>
    {
        private readonly IEnumerable<T> _source;

        public AsyncEnumerableWrapper(IEnumerable<T> source) => _source = source;

        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        {
            return new AsyncEnumeratorWrapper<T>(_source.GetEnumerator());
        }
    }

    private class AsyncEnumeratorWrapper<T> : IAsyncEnumerator<T>
    {
        private readonly IEnumerator<T> _inner;

        public AsyncEnumeratorWrapper(IEnumerator<T> inner) => _inner = inner;
        public T Current => _inner.Current;
        public ValueTask DisposeAsync() { _inner.Dispose(); return ValueTask.CompletedTask; }
        public ValueTask<bool> MoveNextAsync() => ValueTask.FromResult(_inner.MoveNext());
    }

    // BuildMockDbSet helper
    public static Mock<DbSet<T>> BuildMockDbSet<T>(this IQueryable<T> source) where T : class
    {
        var mockSet = new Mock<DbSet<T>>();

        mockSet.As<IAsyncEnumerable<T>>()
            .Setup(m => m.GetAsyncEnumerator(It.IsAny<CancellationToken>()))
            .Returns(new TestAsyncEnumerator<T>(source.GetEnumerator()));

        mockSet.As<IQueryable<T>>()
            .Setup(m => m.Provider)
            .Returns(new TestAsyncQueryProvider<T>(source.Provider));

        mockSet.As<IQueryable<T>>().Setup(m => m.Expression).Returns(source.Expression);
        mockSet.As<IQueryable<T>>().Setup(m => m.ElementType).Returns(source.ElementType);
        mockSet.As<IQueryable<T>>().Setup(m => m.GetEnumerator()).Returns(() => source.GetEnumerator());

        return mockSet;
    }
}

// Test async query provider for EF Core
public class TestAsyncQueryProvider<TEntity> : IAsyncQueryProvider
{
    private readonly IQueryProvider _inner;

    public TestAsyncQueryProvider(IQueryProvider inner) => _inner = inner;

    public IQueryable CreateQuery(Expression expression) => new TestAsyncEnumerable<TEntity>(expression);
    public IQueryable<TElement> CreateQuery<TElement>(Expression expression) => new TestAsyncEnumerable<TElement>(expression);
    public object? Execute(Expression expression) => _inner.Execute(expression);
    public TResult Execute<TResult>(Expression expression) => _inner.Execute<TResult>(expression);
    public TResult ExecuteAsync<TResult>(Expression expression, CancellationToken cancellationToken = default)
    {
        var resultType = typeof(TResult).GetGenericArguments()[0];
        var executionResult = typeof(IQueryProvider)
            .GetMethod(name: nameof(IQueryProvider.Execute), genericParameterCount: 1, types: new[] { typeof(Expression) })!
            .MakeGenericMethod(resultType)
            .Invoke(_inner, new[] { expression });

        return (TResult)typeof(Task).GetMethod(nameof(Task.FromResult))!
            .MakeGenericMethod(resultType)
            .Invoke(null, new[] { executionResult })!;
    }
}

public class TestAsyncEnumerable<T> : EnumerableQuery<T>, IAsyncEnumerable<T>, IQueryable<T>
{
    public TestAsyncEnumerable(IEnumerable<T> enumerable) : base(enumerable) { }
    public TestAsyncEnumerable(Expression expression) : base(expression) { }
    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default) =>
        new TestAsyncEnumerator<T>(this.AsEnumerable().GetEnumerator());
    IQueryProvider IQueryable.Provider => new TestAsyncQueryProvider<T>(this);
}

public class TestAsyncEnumerator<T> : IAsyncEnumerator<T>
{
    private readonly IEnumerator<T> _inner;
    public TestAsyncEnumerator(IEnumerator<T> inner) => _inner = inner;
    public T Current => _inner.Current;
    public ValueTask DisposeAsync() { _inner.Dispose(); return ValueTask.CompletedTask; }
    public ValueTask<bool> MoveNextAsync() => ValueTask.FromResult(_inner.MoveNext());
}
