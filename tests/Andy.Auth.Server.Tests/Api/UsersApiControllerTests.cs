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
using Xunit;

namespace Andy.Auth.Server.Tests.Api;

public class UsersApiControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ILogger<UsersApiController>> _loggerMock;
    private readonly UsersApiController _controller;

    public UsersApiControllerTests()
    {
        // Create in-memory database
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        // Setup UserManager mock
        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _auditServiceMock = new Mock<IAuditService>();
        _loggerMock = new Mock<ILogger<UsersApiController>>();

        _controller = new UsersApiController(
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

    // ==================== SearchUsers Tests ====================

    [Fact]
    public async Task SearchUsers_WithValidQuery_ReturnsMatchingUsers()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "john.doe@test.com", UserName = "john.doe@test.com", FullName = "John Doe" },
            new() { Id = "user-2", Email = "jane.smith@test.com", UserName = "jane.smith@test.com", FullName = "Jane Smith" },
            new() { Id = "user-3", Email = "bob.williams@test.com", UserName = "bob.williams@test.com", FullName = "Bob Williams" }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("john");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().ContainSingle();
        searchResults[0].Email.Should().Be("john.doe@test.com");
    }

    [Fact]
    public async Task SearchUsers_ByFullName_ReturnsMatchingUsers()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "user1@test.com", UserName = "user1@test.com", FullName = "John Doe" },
            new() { Id = "user-2", Email = "user2@test.com", UserName = "user2@test.com", FullName = "Jane Smith" }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("doe");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().ContainSingle();
        searchResults[0].FullName.Should().Be("John Doe");
    }

    [Fact]
    public async Task SearchUsers_ShortQuery_ReturnsEmpty()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "test@test.com", UserName = "test@test.com" }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("t");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().BeEmpty();
    }

    [Fact]
    public async Task SearchUsers_EmptyQuery_ReturnsEmpty()
    {
        // Act
        var result = await _controller.SearchUsers("");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().BeEmpty();
    }

    [Fact]
    public async Task SearchUsers_RespectsLimit()
    {
        // Arrange
        var users = Enumerable.Range(1, 30)
            .Select(i => new ApplicationUser
            {
                Id = $"user-{i}",
                Email = $"testuser{i}@test.com",
                UserName = $"testuser{i}@test.com"
            })
            .AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("testuser", limit: 10);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().HaveCount(10);
    }

    [Fact]
    public async Task SearchUsers_LimitCappedAt100()
    {
        // Arrange
        var users = Enumerable.Range(1, 150)
            .Select(i => new ApplicationUser
            {
                Id = $"user-{i}",
                Email = $"testuser{i}@test.com",
                UserName = $"testuser{i}@test.com"
            })
            .AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("testuser", limit: 200);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().HaveCount(100);
    }

    [Fact]
    public async Task SearchUsers_ExcludesDeletedUsers()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "active@test.com", UserName = "active@test.com" },
            new() { Id = "user-2", Email = "deleted@test.com", UserName = "deleted@test.com", DeletedAt = DateTime.UtcNow }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("test.com");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().ContainSingle();
        searchResults[0].Email.Should().Be("active@test.com");
    }

    [Fact]
    public async Task SearchUsers_IsCaseInsensitive()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "John.Doe@Test.COM", UserName = "John.Doe@Test.COM", FullName = "John Doe" }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("john");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().ContainSingle();
    }

    [Fact]
    public async Task SearchUsers_ReturnsCorrectFields()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new()
            {
                Id = "user-1",
                Email = "john@test.com",
                UserName = "johndoe",
                FullName = "John Doe",
                EmailConfirmed = true,
                TwoFactorEnabled = true,
                LockoutEnd = DateTimeOffset.UtcNow.AddDays(1) // Locked out
            }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);

        // Act
        var result = await _controller.SearchUsers("john");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var searchResults = okResult.Value.Should().BeAssignableTo<List<UserSearchResult>>().Subject;
        searchResults.Should().ContainSingle();

        var user = searchResults[0];
        user.Id.Should().Be("user-1");
        user.Email.Should().Be("john@test.com");
        user.UserName.Should().Be("johndoe");
        user.FullName.Should().Be("John Doe");
        user.EmailConfirmed.Should().BeTrue();
        user.TwoFactorEnabled.Should().BeTrue();
        user.IsLockedOut.Should().BeTrue();
    }

    // ==================== ListUsers Tests ====================

    [Fact]
    public async Task ListUsers_ReturnsUsersWithPagination()
    {
        // Arrange
        var users = Enumerable.Range(1, 25)
            .Select(i => new ApplicationUser
            {
                Id = $"user-{i}",
                Email = $"user{i}@test.com",
                UserName = $"user{i}@test.com",
                CreatedAt = DateTime.UtcNow.AddDays(-i)
            })
            .AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers(page: 1, pageSize: 10);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<UserListResponse>().Subject;
        response.Users.Should().HaveCount(10);
        response.Total.Should().Be(25);
        response.Page.Should().Be(1);
        response.PageSize.Should().Be(10);
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
        var response = okResult.Value.Should().BeOfType<UserListResponse>().Subject;
        response.Users.Should().ContainSingle();
        response.Users[0].Email.Should().Be("john@test.com");
    }

    [Fact]
    public async Task ListUsers_FiltersByIsActive()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new() { Id = "user-1", Email = "active@test.com", IsActive = true, CreatedAt = DateTime.UtcNow },
            new() { Id = "user-2", Email = "inactive@test.com", IsActive = false, CreatedAt = DateTime.UtcNow }
        }.AsQueryable();

        _userManagerMock.Setup(x => x.Users).Returns(users.BuildMockDbSet().Object);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.ListUsers(isActive: true);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<UserListResponse>().Subject;
        response.Users.Should().ContainSingle();
        response.Users[0].Email.Should().Be("active@test.com");
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
        var response = okResult.Value.Should().BeOfType<UserListResponse>().Subject;
        response.Users.Should().ContainSingle();
        response.Users[0].Email.Should().Be("active@test.com");
    }

    // ==================== GetUser Tests ====================

    [Fact]
    public async Task GetUser_ReturnsUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com",
            FullName = "Test User",
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.GetUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<UserDto>().Subject;
        dto.Id.Should().Be("user-1");
        dto.Email.Should().Be("user@test.com");
        dto.FullName.Should().Be("Test User");
        dto.Roles.Should().Contain("User");
    }

    [Fact]
    public async Task GetUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

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
    public async Task CreateUser_CreatesAndReturnsUser()
    {
        // Arrange
        var request = new CreateUserRequest
        {
            Email = "new@test.com",
            FullName = "New User",
            Password = "Password123!",
            IsAdmin = false,
            MustChangePassword = true
        };

        _userManagerMock.Setup(x => x.FindByEmailAsync("new@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), "Password123!"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        var createdResult = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var dto = createdResult.Value.Should().BeOfType<UserDto>().Subject;
        dto.Email.Should().Be("new@test.com");
        dto.FullName.Should().Be("New User");
        dto.MustChangePassword.Should().BeTrue();
    }

    [Fact]
    public async Task CreateUser_CreateAdminUser()
    {
        // Arrange
        var request = new CreateUserRequest
        {
            Email = "admin@test.com",
            FullName = "Admin User",
            Password = "Password123!",
            IsAdmin = true
        };

        _userManagerMock.Setup(x => x.FindByEmailAsync("admin@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Admin"))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "Admin" });

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        result.Should().BeOfType<CreatedAtActionResult>();
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Admin"), Times.Once);
    }

    [Fact]
    public async Task CreateUser_ReturnsBadRequestForDuplicateEmail()
    {
        // Arrange
        var existingUser = new ApplicationUser { Id = "user-1", Email = "existing@test.com" };
        _userManagerMock.Setup(x => x.FindByEmailAsync("existing@test.com")).ReturnsAsync(existingUser);

        var request = new CreateUserRequest
        {
            Email = "existing@test.com",
            FullName = "Test",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task CreateUser_AllowsEmailReuseForDeletedUser()
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
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        var request = new CreateUserRequest
        {
            Email = "reuse@test.com",
            FullName = "New User",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.CreateUser(request);

        // Assert
        result.Should().BeOfType<CreatedAtActionResult>();
        _userManagerMock.Verify(x => x.DeleteAsync(deletedUser), Times.Once);
    }

    // ==================== UpdateUser Tests ====================

    [Fact]
    public async Task UpdateUser_UpdatesAndReturnsUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com",
            FullName = "Old Name"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });

        var request = new UpdateUserRequest { FullName = "New Name" };

        // Act
        var result = await _controller.UpdateUser("user-1", request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<UserDto>().Subject;
        dto.FullName.Should().Be("New Name");
    }

    [Fact]
    public async Task UpdateUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.UpdateUser("non-existent", new UpdateUserRequest());

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== DeleteUser Tests ====================

    [Fact]
    public async Task DeleteUser_SoftDeletesUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-2",
            Email = "delete@test.com"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-2")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.DeleteUser("user-2");

        // Assert
        result.Should().BeOfType<NoContentResult>();
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

    // ==================== SuspendUser Tests ====================

    [Fact]
    public async Task SuspendUser_SuspendsUser()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });

        var request = new SuspendUserRequest { Reason = "Policy violation" };

        // Act
        var result = await _controller.SuspendUser("user-1", request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<UserDto>().Subject;
        dto.IsSuspended.Should().BeTrue();
        dto.SuspensionReason.Should().Be("Policy violation");
    }

    [Fact]
    public async Task SuspendUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.SuspendUser("non-existent", new SuspendUserRequest());

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
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
            SuspensionReason = "Previous reason",
            SuspendedAt = DateTime.UtcNow.AddDays(-1)
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.UnsuspendUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<UserDto>().Subject;
        dto.IsSuspended.Should().BeFalse();
        dto.SuspensionReason.Should().BeNull();
    }

    [Fact]
    public async Task UnsuspendUser_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.UnsuspendUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== ChangeRole Tests ====================

    [Fact]
    public async Task ChangeRole_ChangesUserRole()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "user@test.com"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "Admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });
        _userManagerMock.Setup(x => x.RemoveFromRolesAsync(user, It.IsAny<IEnumerable<string>>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(user, "Admin"))
            .ReturnsAsync(IdentityResult.Success);

        var request = new ChangeRoleRequest { Role = "Admin" };

        // Act
        var result = await _controller.ChangeRole("user-1", request);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        _userManagerMock.Verify(x => x.AddToRoleAsync(user, "Admin"), Times.Once);
    }

    [Fact]
    public async Task ChangeRole_ReturnsBadRequestForInvalidRole()
    {
        // Arrange
        var request = new ChangeRoleRequest { Role = "SuperAdmin" };

        // Act
        var result = await _controller.ChangeRole("user-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("Invalid role");
    }

    [Fact]
    public async Task ChangeRole_ReturnsBadRequestForLastAdminDemotion()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "admin-1",
            Email = "admin@test.com"
        };
        _userManagerMock.Setup(x => x.FindByIdAsync("admin-1")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "Admin")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.GetUsersInRoleAsync("Admin")).ReturnsAsync(new List<ApplicationUser> { user });

        var request = new ChangeRoleRequest { Role = "User" };

        // Act
        var result = await _controller.ChangeRole("admin-1", request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("last admin");
    }

    [Fact]
    public async Task ChangeRole_AllowsDemotionWhenMultipleAdmins()
    {
        // Arrange
        var user1 = new ApplicationUser { Id = "admin-1", Email = "admin1@test.com" };
        var user2 = new ApplicationUser { Id = "admin-2", Email = "admin2@test.com" };

        _userManagerMock.Setup(x => x.FindByIdAsync("admin-1")).ReturnsAsync(user1);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user1, "Admin")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.GetUsersInRoleAsync("Admin")).ReturnsAsync(new List<ApplicationUser> { user1, user2 });
        _userManagerMock.Setup(x => x.GetRolesAsync(user1)).ReturnsAsync(new List<string> { "Admin" });
        _userManagerMock.Setup(x => x.RemoveFromRolesAsync(user1, It.IsAny<IEnumerable<string>>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.AddToRoleAsync(user1, "User"))
            .ReturnsAsync(IdentityResult.Success);

        var request = new ChangeRoleRequest { Role = "User" };

        // Act
        var result = await _controller.ChangeRole("admin-1", request);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
    }

    [Fact]
    public async Task ChangeRole_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.ChangeRole("non-existent", new ChangeRoleRequest { Role = "User" });

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }
}

// Extension for mocking IQueryable with DbSet
public static class MockDbSetExtensions
{
    public static Mock<DbSet<T>> BuildMockDbSet<T>(this IQueryable<T> source) where T : class
    {
        var mock = new Mock<DbSet<T>>();

        mock.As<IAsyncEnumerable<T>>()
            .Setup(m => m.GetAsyncEnumerator(It.IsAny<CancellationToken>()))
            .Returns(new TestAsyncEnumerator<T>(source.GetEnumerator()));

        mock.As<IQueryable<T>>()
            .Setup(m => m.Provider)
            .Returns(new TestAsyncQueryProvider<T>(source.Provider));

        mock.As<IQueryable<T>>()
            .Setup(m => m.Expression)
            .Returns(source.Expression);

        mock.As<IQueryable<T>>()
            .Setup(m => m.ElementType)
            .Returns(source.ElementType);

        mock.As<IQueryable<T>>()
            .Setup(m => m.GetEnumerator())
            .Returns(source.GetEnumerator());

        return mock;
    }
}

// Async query provider for testing
internal class TestAsyncQueryProvider<TEntity> : IAsyncQueryProvider
{
    private readonly IQueryProvider _inner;

    internal TestAsyncQueryProvider(IQueryProvider inner)
    {
        _inner = inner;
    }

    public IQueryable CreateQuery(System.Linq.Expressions.Expression expression)
    {
        return new TestAsyncEnumerable<TEntity>(expression);
    }

    public IQueryable<TElement> CreateQuery<TElement>(System.Linq.Expressions.Expression expression)
    {
        return new TestAsyncEnumerable<TElement>(expression);
    }

    public object? Execute(System.Linq.Expressions.Expression expression)
    {
        return _inner.Execute(expression);
    }

    public TResult Execute<TResult>(System.Linq.Expressions.Expression expression)
    {
        return _inner.Execute<TResult>(expression);
    }

    public TResult ExecuteAsync<TResult>(System.Linq.Expressions.Expression expression, CancellationToken cancellationToken = default)
    {
        var expectedResultType = typeof(TResult).GetGenericArguments()[0];
        var executionResult = typeof(IQueryProvider)
            .GetMethod(
                name: nameof(IQueryProvider.Execute),
                genericParameterCount: 1,
                types: new[] { typeof(System.Linq.Expressions.Expression) })!
            .MakeGenericMethod(expectedResultType)
            .Invoke(this, new[] { expression });

        return (TResult)typeof(Task).GetMethod(nameof(Task.FromResult))!
            .MakeGenericMethod(expectedResultType)
            .Invoke(null, new[] { executionResult })!;
    }
}

internal class TestAsyncEnumerable<T> : EnumerableQuery<T>, IAsyncEnumerable<T>, IQueryable<T>
{
    public TestAsyncEnumerable(IEnumerable<T> enumerable) : base(enumerable) { }
    public TestAsyncEnumerable(System.Linq.Expressions.Expression expression) : base(expression) { }

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
    {
        return new TestAsyncEnumerator<T>(this.AsEnumerable().GetEnumerator());
    }

    IQueryProvider IQueryable.Provider => new TestAsyncQueryProvider<T>(this);
}

internal class TestAsyncEnumerator<T> : IAsyncEnumerator<T>
{
    private readonly IEnumerator<T> _inner;

    public TestAsyncEnumerator(IEnumerator<T> inner)
    {
        _inner = inner;
    }

    public T Current => _inner.Current;

    public ValueTask DisposeAsync()
    {
        _inner.Dispose();
        return ValueTask.CompletedTask;
    }

    public ValueTask<bool> MoveNextAsync()
    {
        return ValueTask.FromResult(_inner.MoveNext());
    }
}
