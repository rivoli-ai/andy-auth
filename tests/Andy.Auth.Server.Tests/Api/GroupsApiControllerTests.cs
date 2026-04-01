using Andy.Auth.Server.Controllers.Api;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;

namespace Andy.Auth.Server.Tests.Api;

public class GroupsApiControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ILogger<GroupsApiController>> _loggerMock;
    private readonly GroupsApiController _controller;

    public GroupsApiControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _auditServiceMock = new Mock<IAuditService>();
        _loggerMock = new Mock<ILogger<GroupsApiController>>();

        _controller = new GroupsApiController(
            _context,
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

    private async Task<Group> CreateTestGroupAsync(string code, string name, bool isActive = true, string source = "local")
    {
        var group = new Group
        {
            Id = Guid.NewGuid(),
            Code = code,
            Name = name,
            IsActive = isActive,
            Source = source,
            CreatedAt = DateTime.UtcNow
        };
        _context.Groups.Add(group);
        await _context.SaveChangesAsync();
        return group;
    }

    private async Task<ApplicationUser> CreateTestUserAsync(string id, string email, string? fullName = null)
    {
        var user = new ApplicationUser
        {
            Id = id,
            Email = email,
            UserName = email,
            FullName = fullName
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }

    // ==================== ListGroups Tests ====================

    [Fact]
    public async Task ListGroups_ReturnsAllGroups()
    {
        // Arrange
        await CreateTestGroupAsync("engineering", "Engineering");
        await CreateTestGroupAsync("devops", "DevOps");

        // Act
        var result = await _controller.ListGroups();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<GroupListResponse>().Subject;
        response.Groups.Should().HaveCount(2);
    }

    [Fact]
    public async Task ListGroups_FiltersBySearch()
    {
        // Arrange
        await CreateTestGroupAsync("engineering", "Engineering Team");
        await CreateTestGroupAsync("devops", "DevOps Team");
        await CreateTestGroupAsync("sales", "Sales Department");

        // Act
        var result = await _controller.ListGroups(search: "Team");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<GroupListResponse>().Subject;
        response.Groups.Should().HaveCount(2);
        response.Groups.Should().Contain(g => g.Code == "engineering");
        response.Groups.Should().Contain(g => g.Code == "devops");
    }

    [Fact]
    public async Task ListGroups_FiltersByCode()
    {
        // Arrange
        await CreateTestGroupAsync("engineering", "Engineering");
        await CreateTestGroupAsync("devops", "DevOps");

        // Act
        var result = await _controller.ListGroups(search: "eng");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<GroupListResponse>().Subject;
        response.Groups.Should().ContainSingle(g => g.Code == "engineering");
    }

    [Fact]
    public async Task ListGroups_FiltersByActiveStatus()
    {
        // Arrange
        await CreateTestGroupAsync("active-group", "Active Group", isActive: true);
        await CreateTestGroupAsync("inactive-group", "Inactive Group", isActive: false);

        // Act
        var result = await _controller.ListGroups(isActive: true);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<GroupListResponse>().Subject;
        response.Groups.Should().ContainSingle(g => g.Code == "active-group");
    }

    [Fact]
    public async Task ListGroups_IncludesMemberCount()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user1 = await CreateTestUserAsync("user-1", "user1@test.com");
        var user2 = await CreateTestUserAsync("user-2", "user2@test.com");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user1.Id, GroupId = group.Id });
        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user2.Id, GroupId = group.Id });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.ListGroups();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<GroupListResponse>().Subject;
        response.Groups.Should().ContainSingle().Which.MemberCount.Should().Be(2);
    }

    [Fact]
    public async Task ListGroups_ExcludesExpiredMembersFromCount()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user1 = await CreateTestUserAsync("user-1", "user1@test.com");
        var user2 = await CreateTestUserAsync("user-2", "user2@test.com");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user1.Id, GroupId = group.Id });
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user2.Id,
            GroupId = group.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(-1) // Expired
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.ListGroups();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<GroupListResponse>().Subject;
        response.Groups.Should().ContainSingle().Which.MemberCount.Should().Be(1);
    }

    // ==================== GetGroup Tests ====================

    [Fact]
    public async Task GetGroup_ReturnsGroupWithMembers()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user = await CreateTestUserAsync("user-1", "user@test.com", "Test User");

        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            Source = "manual"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetGroup(group.Id);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupDetailDto>().Subject;
        dto.Code.Should().Be("test-group");
        dto.Members.Should().ContainSingle();
        dto.Members[0].Email.Should().Be("user@test.com");
        dto.Members[0].FullName.Should().Be("Test User");
    }

    [Fact]
    public async Task GetGroup_ReturnsNotFoundForNonExistent()
    {
        // Act
        var result = await _controller.GetGroup(Guid.NewGuid());

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task GetGroup_ExcludesExpiredMembers()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var activeUser = await CreateTestUserAsync("user-1", "active@test.com");
        var expiredUser = await CreateTestUserAsync("user-2", "expired@test.com");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = activeUser.Id, GroupId = group.Id });
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = expiredUser.Id,
            GroupId = group.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(-1)
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetGroup(group.Id);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupDetailDto>().Subject;
        dto.Members.Should().ContainSingle().Which.Email.Should().Be("active@test.com");
    }

    // ==================== GetGroupByCode Tests ====================

    [Fact]
    public async Task GetGroupByCode_ReturnsGroup()
    {
        // Arrange
        await CreateTestGroupAsync("my-group", "My Group");

        // Act
        var result = await _controller.GetGroupByCode("my-group");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupDetailDto>().Subject;
        dto.Code.Should().Be("my-group");
        dto.Name.Should().Be("My Group");
    }

    [Fact]
    public async Task GetGroupByCode_ReturnsNotFoundForNonExistent()
    {
        // Act
        var result = await _controller.GetGroupByCode("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== CreateGroup Tests ====================

    [Fact]
    public async Task CreateGroup_CreatesAndReturnsGroup()
    {
        // Arrange
        var request = new CreateGroupRequest
        {
            Code = "new-group",
            Name = "New Group",
            Description = "A new group"
        };

        // Act
        var result = await _controller.CreateGroup(request);

        // Assert
        var createdResult = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var dto = createdResult.Value.Should().BeOfType<GroupDto>().Subject;
        dto.Code.Should().Be("new-group");
        dto.Name.Should().Be("New Group");
        dto.Description.Should().Be("A new group");
        dto.IsActive.Should().BeTrue();
        dto.Source.Should().Be("local");
        dto.MemberCount.Should().Be(0);

        // Verify persisted
        var savedGroup = await _context.Groups.FirstOrDefaultAsync(g => g.Code == "new-group");
        savedGroup.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateGroup_ReturnsBadRequestForDuplicateCode()
    {
        // Arrange
        await CreateTestGroupAsync("existing-group", "Existing Group");

        var request = new CreateGroupRequest
        {
            Code = "existing-group",
            Name = "Another Group"
        };

        // Act
        var result = await _controller.CreateGroup(request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("already exists");
    }

    [Fact]
    public async Task CreateGroup_LogsAudit()
    {
        // Arrange
        var request = new CreateGroupRequest
        {
            Code = "audit-test",
            Name = "Audit Test Group"
        };

        // Act
        await _controller.CreateGroup(request);

        // Assert
        _auditServiceMock.Verify(
            x => x.LogAsync(
                "GroupCreated",
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string?>(),
                "audit-test",
                It.IsAny<string?>(),
                It.IsAny<string?>()),
            Times.Once);
    }

    // ==================== UpdateGroup Tests ====================

    [Fact]
    public async Task UpdateGroup_UpdatesName()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Old Name");

        var request = new UpdateGroupRequest { Name = "New Name" };

        // Act
        var result = await _controller.UpdateGroup(group.Id, request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupDto>().Subject;
        dto.Name.Should().Be("New Name");

        var savedGroup = await _context.Groups.FindAsync(group.Id);
        savedGroup!.Name.Should().Be("New Name");
    }

    [Fact]
    public async Task UpdateGroup_UpdatesDescription()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");

        var request = new UpdateGroupRequest { Description = "Updated description" };

        // Act
        var result = await _controller.UpdateGroup(group.Id, request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupDto>().Subject;
        dto.Description.Should().Be("Updated description");
    }

    [Fact]
    public async Task UpdateGroup_UpdatesIsActive()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group", isActive: true);

        var request = new UpdateGroupRequest { IsActive = false };

        // Act
        var result = await _controller.UpdateGroup(group.Id, request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupDto>().Subject;
        dto.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateGroup_ReturnsNotFoundForNonExistent()
    {
        // Arrange
        var request = new UpdateGroupRequest { Name = "New Name" };

        // Act
        var result = await _controller.UpdateGroup(Guid.NewGuid(), request);

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== DeleteGroup Tests ====================

    [Fact]
    public async Task DeleteGroup_DeletesGroupAndMemberships()
    {
        // Arrange
        var group = await CreateTestGroupAsync("delete-me", "Delete Me");
        var user = await CreateTestUserAsync("user-1", "user@test.com");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = group.Id });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.DeleteGroup(group.Id);

        // Assert
        result.Should().BeOfType<NoContentResult>();

        var deletedGroup = await _context.Groups.FindAsync(group.Id);
        deletedGroup.Should().BeNull();

        var memberships = await _context.UserGroups.Where(ug => ug.GroupId == group.Id).ToListAsync();
        memberships.Should().BeEmpty();
    }

    [Fact]
    public async Task DeleteGroup_ReturnsNotFoundForNonExistent()
    {
        // Act
        var result = await _controller.DeleteGroup(Guid.NewGuid());

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task DeleteGroup_ReturnsBadRequestForExternalGroup()
    {
        // Arrange
        var group = await CreateTestGroupAsync("external-group", "External Group", source: "ldap");

        // Act
        var result = await _controller.DeleteGroup(group.Id);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value as dynamic;
        ((string)error!.error).Should().Contain("external sources");
    }

    // ==================== AddMember Tests ====================

    [Fact]
    public async Task AddMember_AddsMemberToGroup()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user = await CreateTestUserAsync("user-1", "user@test.com", "Test User");

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        var request = new AddMemberRequest { UserId = "user-1" };

        // Act
        var result = await _controller.AddMember(group.Id, request);

        // Assert
        var createdResult = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var dto = createdResult.Value.Should().BeOfType<GroupMemberDto>().Subject;
        dto.UserId.Should().Be("user-1");
        dto.Email.Should().Be("user@test.com");
        dto.FullName.Should().Be("Test User");
        dto.Source.Should().Be("manual");

        var membership = await _context.UserGroups.FirstOrDefaultAsync(ug => ug.UserId == "user-1" && ug.GroupId == group.Id);
        membership.Should().NotBeNull();
    }

    [Fact]
    public async Task AddMember_FindsUserByEmail()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user = await CreateTestUserAsync("user-1", "user@test.com");

        _userManagerMock.Setup(x => x.FindByIdAsync("user@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);

        var request = new AddMemberRequest { UserId = "user@test.com" };

        // Act
        var result = await _controller.AddMember(group.Id, request);

        // Assert
        result.Should().BeOfType<CreatedAtActionResult>();
    }

    [Fact]
    public async Task AddMember_ReturnsNotFoundForNonExistentGroup()
    {
        // Arrange
        var request = new AddMemberRequest { UserId = "user-1" };

        // Act
        var result = await _controller.AddMember(Guid.NewGuid(), request);

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task AddMember_ReturnsNotFoundForNonExistentUser()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");

        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        var request = new AddMemberRequest { UserId = "non-existent" };

        // Act
        var result = await _controller.AddMember(group.Id, request);

        // Assert
        var notFound = result.Should().BeOfType<NotFoundObjectResult>().Subject;
        var error = notFound.Value as dynamic;
        ((string)error!.error).Should().Contain("User not found");
    }

    [Fact]
    public async Task AddMember_UpdatesExpirationForExistingMember()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user = await CreateTestUserAsync("user-1", "user@test.com");

        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow.AddDays(-10)
        });
        await _context.SaveChangesAsync();

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        var newExpiration = DateTime.UtcNow.AddDays(30);
        var request = new AddMemberRequest { UserId = "user-1", ExpiresAt = newExpiration };

        // Act
        var result = await _controller.AddMember(group.Id, request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<GroupMemberDto>().Subject;
        dto.ExpiresAt.Should().BeCloseTo(newExpiration, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task AddMember_SetsExpirationDate()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user = await CreateTestUserAsync("user-1", "user@test.com");

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        var expiresAt = DateTime.UtcNow.AddDays(7);
        var request = new AddMemberRequest { UserId = "user-1", ExpiresAt = expiresAt };

        // Act
        var result = await _controller.AddMember(group.Id, request);

        // Assert
        var createdResult = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var dto = createdResult.Value.Should().BeOfType<GroupMemberDto>().Subject;
        dto.ExpiresAt.Should().BeCloseTo(expiresAt, TimeSpan.FromSeconds(1));
    }

    // ==================== RemoveMember Tests ====================

    [Fact]
    public async Task RemoveMember_RemovesMemberFromGroup()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");
        var user = await CreateTestUserAsync("user-1", "user@test.com");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = group.Id });
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.RemoveMember(group.Id, user.Id);

        // Assert
        result.Should().BeOfType<NoContentResult>();

        var membership = await _context.UserGroups.FirstOrDefaultAsync(ug => ug.UserId == user.Id && ug.GroupId == group.Id);
        membership.Should().BeNull();
    }

    [Fact]
    public async Task RemoveMember_ReturnsNotFoundForNonExistentMembership()
    {
        // Arrange
        var group = await CreateTestGroupAsync("test-group", "Test Group");

        // Act
        var result = await _controller.RemoveMember(group.Id, "non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ==================== GetGroupsForUser Tests ====================

    [Fact]
    public async Task GetGroupsForUser_ReturnsUserGroups()
    {
        // Arrange
        var user = await CreateTestUserAsync("user-1", "user@test.com");
        var group1 = await CreateTestGroupAsync("group-1", "Group 1");
        var group2 = await CreateTestGroupAsync("group-2", "Group 2");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = group1.Id });
        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = group2.Id });
        await _context.SaveChangesAsync();

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _controller.GetGroupsForUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var groups = okResult.Value.Should().BeAssignableTo<List<GroupDto>>().Subject;
        groups.Should().HaveCount(2);
    }

    [Fact]
    public async Task GetGroupsForUser_ExcludesExpiredMemberships()
    {
        // Arrange
        var user = await CreateTestUserAsync("user-1", "user@test.com");
        var activeGroup = await CreateTestGroupAsync("active-group", "Active Group");
        var expiredGroup = await CreateTestGroupAsync("expired-group", "Expired Group");

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = activeGroup.Id });
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = expiredGroup.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(-1)
        });
        await _context.SaveChangesAsync();

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _controller.GetGroupsForUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var groups = okResult.Value.Should().BeAssignableTo<List<GroupDto>>().Subject;
        groups.Should().ContainSingle().Which.Code.Should().Be("active-group");
    }

    [Fact]
    public async Task GetGroupsForUser_ExcludesInactiveGroups()
    {
        // Arrange
        var user = await CreateTestUserAsync("user-1", "user@test.com");
        var activeGroup = await CreateTestGroupAsync("active-group", "Active Group", isActive: true);
        var inactiveGroup = await CreateTestGroupAsync("inactive-group", "Inactive Group", isActive: false);

        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = activeGroup.Id });
        _context.UserGroups.Add(new UserGroup { Id = Guid.NewGuid(), UserId = user.Id, GroupId = inactiveGroup.Id });
        await _context.SaveChangesAsync();

        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _controller.GetGroupsForUser("user-1");

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var groups = okResult.Value.Should().BeAssignableTo<List<GroupDto>>().Subject;
        groups.Should().ContainSingle().Which.Code.Should().Be("active-group");
    }

    [Fact]
    public async Task GetGroupsForUser_ReturnsNotFoundForNonExistentUser()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.GetGroupsForUser("non-existent");

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }
}
