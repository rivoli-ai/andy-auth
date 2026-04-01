using Andy.Auth.Server.Controllers.Api;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;

namespace Andy.Auth.Server.Tests.Api;

public class McpUsersControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ILogger<McpUsersController>> _loggerMock;
    private readonly McpUsersController _controller;

    public McpUsersControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _auditServiceMock = new Mock<IAuditService>();
        _loggerMock = new Mock<ILogger<McpUsersController>>();

        _controller = new McpUsersController(
            _userManagerMock.Object,
            _auditServiceMock.Object,
            _loggerMock.Object);

        // Setup HttpContext with user claims
        var claims = new List<Claim>
        {
            new("sub", "admin-1"),
            new("email", "admin@test.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== ListUsers Tests ====================

    [Fact]
    public async Task ListUsers_ReturnsUsers()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "user1@test.com", FullName = "User One", CreatedAt = DateTime.UtcNow },
            new() { Id = "user-2", Email = "user2@test.com", FullName = "User Two", CreatedAt = DateTime.UtcNow }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((int)response!.count).Should().Be(2);
    }

    [Fact]
    public async Task ListUsers_RespectsLimit()
    {
        // Arrange
        var users = Enumerable.Range(1, 100)
            .Select(i => new ApplicationUser
            {
                Id = $"user-{i}",
                Email = $"user{i}@test.com",
                CreatedAt = DateTime.UtcNow
            })
            .AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers(limit: 10);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((int)response!.count).Should().Be(10);
    }

    [Fact]
    public async Task ListUsers_LimitCappedAt100()
    {
        // Arrange
        var users = Enumerable.Range(1, 150)
            .Select(i => new ApplicationUser
            {
                Id = $"user-{i}",
                Email = $"user{i}@test.com",
                CreatedAt = DateTime.UtcNow
            })
            .AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers(limit: 200);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((int)response!.count).Should().Be(100);
    }

    [Fact]
    public async Task ListUsers_FiltersBySearch()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "john@test.com", FullName = "John Doe", CreatedAt = DateTime.UtcNow },
            new() { Id = "user-2", Email = "jane@test.com", FullName = "Jane Smith", CreatedAt = DateTime.UtcNow }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers(search: "john");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((int)response!.count).Should().Be(1);
    }

    [Fact]
    public async Task ListUsers_ExcludesDeletedUsers()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "active@test.com", CreatedAt = DateTime.UtcNow },
            new() { Id = "user-2", Email = "deleted@test.com", DeletedAt = DateTime.UtcNow, CreatedAt = DateTime.UtcNow }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((int)response!.count).Should().Be(1);
    }

    // ==================== GetUser Tests ====================

    [Fact]
    public async Task GetUser_ById_ReturnsUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com",
            FullName = "Test User"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.GetUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((string)response!.Email).Should().Be("user@test.com");
    }

    [Fact]
    public async Task GetUser_ByEmail_ReturnsUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com",
            FullName = "Test User"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "Admin" });

        // Act
        var result = await _controller.GetUser("user@test.com");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((string)response!.Id).Should().Be("user-1");
        ((string)response!.Role).Should().Be("Admin");
    }

    [Fact]
    public async Task GetUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.GetUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task GetUser_ReturnsNotFoundForDeletedUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "deleted@test.com",
            DeletedAt = DateTime.UtcNow
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _controller.GetUser("user-1");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== CreateUser Tests ====================

    [Fact]
    public async Task CreateUser_CreatesUser()
    {
        // Arrange
        var request = new McpCreateUserRequest
        {
            Email = "new@test.com",
            Password = "Password123!",
            FullName = "New User"
        };

        _userManagerMock.Setup(x => x.FindByEmailAsync("new@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((bool)response!.success).Should().BeTrue();
        ((string)response!.message).Should().Contain("new@test.com");
    }

    [Fact]
    public async Task CreateUser_CreatesAdminUser()
    {
        // Arrange
        var request = new McpCreateUserRequest
        {
            Email = "admin@test.com",
            Password = "Password123!",
            IsAdmin = true
        };

        _userManagerMock.Setup(x => x.FindByEmailAsync("admin@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Admin"))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Admin"), Times.Once);
    }

    [Fact]
    public async Task CreateUser_ReturnsBadRequestForMissingEmail()
    {
        // Arrange
        var request = new McpCreateUserRequest
        {
            Email = "",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("required");
    }

    [Fact]
    public async Task CreateUser_ReturnsBadRequestForMissingPassword()
    {
        // Arrange
        var request = new McpCreateUserRequest
        {
            Email = "test@test.com",
            Password = ""
        };

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("required");
    }

    [Fact]
    public async Task CreateUser_ReturnsBadRequestForDuplicateEmail()
    {
        // Arrange
        var existingUser = new ApplicationUser { Id = "user-1", Email = "existing@test.com" };
        _userManagerMock.Setup(x => x.FindByEmailAsync("existing@test.com")).ReturnsAsync(existingUser);

        var request = new McpCreateUserRequest
        {
            Email = "existing@test.com",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("already exists");
    }

    [Fact]
    public async Task CreateUser_AllowsReuseOfDeletedUserEmail()
    {
        // Arrange
        var deletedUser = new ApplicationUser
        {
            Id = "user-1",
            Email = "reuse@test.com",
            DeletedAt = DateTime.UtcNow
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("reuse@test.com")).ReturnsAsync(deletedUser);
        _userManagerMock.Setup(x => x.DeleteAsync(deletedUser)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        var request = new McpCreateUserRequest
        {
            Email = "reuse@test.com",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        _userManagerMock.Verify(x => x.DeleteAsync(deletedUser), Times.Once);
    }

    [Fact]
    public async Task CreateUser_UsesEmailPrefixAsDefaultFullName()
    {
        // Arrange
        var request = new McpCreateUserRequest
        {
            Email = "john.doe@test.com",
            Password = "Password123!"
            // No FullName provided
        };

        ApplicationUser? capturedUser = null;
        _userManagerMock.Setup(x => x.FindByEmailAsync("john.doe@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .Callback<ApplicationUser, string>((u, p) => capturedUser = u)
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        await _controller.CreateUser(request);

        // Assert
        capturedUser!.FullName.Should().Be("john.doe");
    }

    // ==================== SuspendUser Tests ====================

    [Fact]
    public async Task SuspendUser_SuspendsUser()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var request = new McpSuspendRequest { Reason = "Policy violation" };

        // Act
        var result = await _controller.SuspendUser("user-1", request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((bool)response!.success).Should().BeTrue();
        user.IsSuspended.Should().BeTrue();
        user.SuspensionReason.Should().Be("Policy violation");
    }

    [Fact]
    public async Task SuspendUser_UsesDefaultReason()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var request = new McpSuspendRequest { Reason = null };

        // Act
        await _controller.SuspendUser("user-1", request);

        // Assert
        user.SuspensionReason.Should().Be("Suspended via MCP");
    }

    [Fact]
    public async Task SuspendUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.SuspendUser("non-existent", new McpSuspendRequest());

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task SuspendUser_ReturnsBadRequestForSystemUser()
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
        var result = await _controller.SuspendUser("system-1", new McpSuspendRequest());

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("system users");
    }

    // ==================== UnsuspendUser Tests ====================

    [Fact]
    public async Task UnsuspendUser_UnsuspendsUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com",
            IsSuspended = true,
            SuspensionReason = "Old reason",
            SuspendedAt = DateTime.UtcNow.AddDays(-1)
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.UnsuspendUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        user.IsSuspended.Should().BeFalse();
        user.SuspensionReason.Should().BeNull();
        user.SuspendedAt.Should().BeNull();
    }

    [Fact]
    public async Task UnsuspendUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.UnsuspendUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== DeleteUser Tests ====================

    [Fact]
    public async Task DeleteUser_SoftDeletesUser()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-2", Email = "delete@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-2")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.DeleteUser("user-2");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        user.DeletedAt.Should().NotBeNull();
        user.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.DeleteUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task DeleteUser_ReturnsBadRequestForSystemUser()
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
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("system users");
    }

    [Fact]
    public async Task DeleteUser_ReturnsBadRequestForSelfDeletion()
    {
        // Arrange - Current user is "admin-1" from claims setup
        var currentUser = new ApplicationUser
        {
            Id = "admin-1",
            Email = "admin@test.com"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("admin-1")).ReturnsAsync(currentUser);

        // Act
        var result = await _controller.DeleteUser("admin-1");

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("your own account");
    }

    // ==================== ChangeRole Tests ====================

    [Fact]
    public async Task ChangeRole_ChangesRole()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "Admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });
        _userManagerMock.Setup(x => x.RemoveFromRolesAsync(user, It.IsAny<IEnumerable<string>>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(user, "Admin"))
            .ReturnsAsync(IdentityResult.Success);

        var request = new McpChangeRoleRequest { Role = "Admin" };

        // Act
        var result = await _controller.ChangeRole("user-1", request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((string)response!.message).Should().Contain("from User to Admin");
    }

    [Fact]
    public async Task ChangeRole_ReturnsBadRequestForInvalidRole()
    {
        // Arrange
        var request = new McpChangeRoleRequest { Role = "SuperAdmin" };

        // Act
        var result = await _controller.ChangeRole("user-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("Admin' or 'User");
    }

    [Fact]
    public async Task ChangeRole_ReturnsBadRequestForLastAdminDemotion()
    {
        // Arrange
        var user = new ApplicationUser { Id = "admin-1", Email = "admin@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("admin-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "Admin")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.GetUsersInRoleAsync("Admin")).ReturnsAsync(new List<ApplicationUser> { user });

        var request = new McpChangeRoleRequest { Role = "User" };

        // Act
        var result = await _controller.ChangeRole("admin-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("last admin");
    }

    [Fact]
    public async Task ChangeRole_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.ChangeRole("non-existent", new McpChangeRoleRequest { Role = "User" });

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== ResetPassword Tests ====================

    [Fact]
    public async Task ResetPassword_ResetsPassword()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.RemovePasswordAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddPasswordAsync(user, "NewPassword123!"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.UpdateSecurityStampAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var request = new McpResetPasswordRequest
        {
            NewPassword = "NewPassword123!",
            MustChangePassword = true
        };

        // Act
        var result = await _controller.ResetPassword("user-1", request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value as dynamic;
        ((bool)response!.success).Should().BeTrue();
        ((bool)response!.must_change_password).Should().BeTrue();
    }

    [Fact]
    public async Task ResetPassword_ReturnsBadRequestForEmptyPassword()
    {
        // Arrange
        var request = new McpResetPasswordRequest { NewPassword = "" };

        // Act
        var result = await _controller.ResetPassword("user-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("required");
    }

    [Fact]
    public async Task ResetPassword_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        var request = new McpResetPasswordRequest { NewPassword = "NewPassword123!" };

        // Act
        var result = await _controller.ResetPassword("non-existent", request);

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task ResetPassword_ReturnsBadRequestOnPasswordRemovalFailure()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.RemovePasswordAsync(user))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Failed to remove password" }));

        var request = new McpResetPasswordRequest { NewPassword = "NewPassword123!" };

        // Act
        var result = await _controller.ResetPassword("user-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("Failed to reset password");
    }

    [Fact]
    public async Task ResetPassword_ReturnsBadRequestOnPasswordAddFailure()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.RemovePasswordAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddPasswordAsync(user, It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Password too weak" }));

        var request = new McpResetPasswordRequest { NewPassword = "weak" };

        // Act
        var result = await _controller.ResetPassword("user-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("Failed to set new password");
    }
}
