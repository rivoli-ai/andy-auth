using Andy.Auth.Server.Data;
using Andy.Auth.Server.Mcp;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Andy.Auth.Server.Tests.Mcp;

public class AuthMcpToolsTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<ILogger<AuthMcpTools>> _loggerMock;
    private readonly AuthMcpTools _tools;

    public AuthMcpToolsTests()
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

        _loggerMock = new Mock<ILogger<AuthMcpTools>>();

        _tools = new AuthMcpTools(_context, _userManagerMock.Object, _loggerMock.Object);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== Group Listing Tests ====================

    [Fact]
    public async Task ListGroups_ReturnsAllGroups()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.ListGroups();

        // Assert
        result.Should().HaveCount(2);
        result.Should().Contain(g => g.Code == "engineering");
        result.Should().Contain(g => g.Code == "sales");
    }

    [Fact]
    public async Task ListGroups_WithSearch_FiltersResults()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.ListGroups(search: "eng");

        // Assert
        result.Should().ContainSingle();
        result[0].Code.Should().Be("engineering");
    }

    [Fact]
    public async Task ListGroups_WithIsActive_FiltersResults()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "sales");
        group.IsActive = false;
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.ListGroups(isActive: true);

        // Assert
        result.Should().ContainSingle();
        result[0].Code.Should().Be("engineering");
    }

    [Fact]
    public async Task ListGroups_EmptyDatabase_ReturnsEmpty()
    {
        // Act
        var result = await _tools.ListGroups();

        // Assert
        result.Should().BeEmpty();
    }

    // ==================== Get Group By ID Tests ====================

    [Fact]
    public async Task GetGroupById_WithExistingId_ReturnsGroupDetail()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");

        // Act
        var result = await _tools.GetGroupById(group.Id.ToString());

        // Assert
        result.Should().NotBeNull();
        result!.Code.Should().Be("engineering");
        result.Name.Should().Be("Engineering Team");
    }

    [Fact]
    public async Task GetGroupById_WithNonExistentId_ReturnsNull()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.GetGroupById(Guid.NewGuid().ToString());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetGroupById_WithInvalidId_ThrowsException()
    {
        // Act & Assert
        var act = async () => await _tools.GetGroupById("not-a-guid");

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Invalid group ID format*");
    }

    [Fact]
    public async Task GetGroupById_IncludesActiveMembers()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com", FullName = "Test User" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.GetGroupById(group.Id.ToString());

        // Assert
        result.Should().NotBeNull();
        result!.Members.Should().ContainSingle();
        result.Members[0].Email.Should().Be("user@test.com");
    }

    // ==================== Get Group Tests ====================

    [Fact]
    public async Task GetGroup_WithExistingCode_ReturnsGroupDetail()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.GetGroup("engineering");

        // Assert
        result.Should().NotBeNull();
        result!.Code.Should().Be("engineering");
        result.Name.Should().Be("Engineering Team");
        result.Members.Should().BeEmpty();
    }

    [Fact]
    public async Task GetGroup_WithNonExistentCode_ReturnsNull()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.GetGroup("non-existent");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetGroup_IncludesActiveMembers()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com", FullName = "Test User" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.GetGroup("engineering");

        // Assert
        result.Should().NotBeNull();
        result!.Members.Should().ContainSingle();
        result.Members[0].Email.Should().Be("user@test.com");
    }

    [Fact]
    public async Task GetGroup_ExcludesExpiredMembers()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow.AddDays(-30),
            ExpiresAt = DateTime.UtcNow.AddDays(-1), // Expired
            Source = "manual"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.GetGroup("engineering");

        // Assert
        result.Should().NotBeNull();
        result!.Members.Should().BeEmpty();
    }

    // ==================== Create Group Tests ====================

    [Fact]
    public async Task CreateGroup_WithValidData_CreatesGroup()
    {
        // Act
        var result = await _tools.CreateGroup("new-group", "New Group", "A new group");

        // Assert
        result.Should().NotBeNull();
        result.Code.Should().Be("new-group");
        result.Name.Should().Be("New Group");
        result.IsActive.Should().BeTrue();
        result.Source.Should().Be("local");

        var dbGroup = await _context.Groups.FirstOrDefaultAsync(g => g.Code == "new-group");
        dbGroup.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateGroup_WithDuplicateCode_ThrowsException()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act & Assert
        var act = async () => await _tools.CreateGroup("engineering", "Another Engineering");

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*already exists*");
    }

    // ==================== Update Group Tests ====================

    [Fact]
    public async Task UpdateGroup_WithValidData_UpdatesGroup()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.UpdateGroup("engineering", name: "Updated Engineering", description: "New description");

        // Assert
        result.Should().NotBeNull();
        result.Name.Should().Be("Updated Engineering");

        var dbGroup = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        dbGroup.Name.Should().Be("Updated Engineering");
        dbGroup.Description.Should().Be("New description");
    }

    [Fact]
    public async Task UpdateGroup_CanDeactivate()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.UpdateGroup("engineering", isActive: false);

        // Assert
        result.IsActive.Should().BeFalse();

        var dbGroup = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        dbGroup.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateGroup_WithNonExistentCode_ThrowsException()
    {
        // Act & Assert
        var act = async () => await _tools.UpdateGroup("non-existent", name: "Test");

        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    // ==================== Delete Group Tests ====================

    [Fact]
    public async Task DeleteGroup_WithLocalGroup_DeletesGroup()
    {
        // Arrange
        await SeedGroupsAsync();

        // Act
        var result = await _tools.DeleteGroup("engineering");

        // Assert
        result.Should().Contain("Successfully deleted");

        var dbGroup = await _context.Groups.FirstOrDefaultAsync(g => g.Code == "engineering");
        dbGroup.Should().BeNull();
    }

    [Fact]
    public async Task DeleteGroup_WithExternalGroup_ThrowsException()
    {
        // Arrange
        _context.Groups.Add(new Group
        {
            Id = Guid.NewGuid(),
            Code = "external-group",
            Name = "External Group",
            Source = "ldap",
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        // Act & Assert
        var act = async () => await _tools.DeleteGroup("external-group");

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*external sources*");
    }

    [Fact]
    public async Task DeleteGroup_WithNonExistentCode_ThrowsException()
    {
        // Act & Assert
        var act = async () => await _tools.DeleteGroup("non-existent");

        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task DeleteGroup_RemovesMemberships()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.DeleteGroup("engineering");

        // Assert
        result.Should().Contain("removed 1 membership");
        var memberships = await _context.UserGroups.Where(ug => ug.GroupId == group.Id).ToListAsync();
        memberships.Should().BeEmpty();
    }

    // ==================== Add User to Group Tests ====================

    [Fact]
    public async Task AddUserToGroup_WithValidData_AddsMembership()
    {
        // Arrange
        await SeedGroupsAsync();
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.AddUserToGroup("engineering", "user-1");

        // Assert
        result.Should().Contain("Successfully added");
        result.Should().Contain("user@test.com");

        var membership = await _context.UserGroups.FirstOrDefaultAsync(ug => ug.UserId == "user-1");
        membership.Should().NotBeNull();
    }

    [Fact]
    public async Task AddUserToGroup_WithEmail_FindsUserByEmail()
    {
        // Arrange
        await SeedGroupsAsync();
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user@test.com")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);

        // Act
        var result = await _tools.AddUserToGroup("engineering", "user@test.com");

        // Assert
        result.Should().Contain("Successfully added");
    }

    [Fact]
    public async Task AddUserToGroup_WithExpiration_SetsExpirationDate()
    {
        // Arrange
        await SeedGroupsAsync();
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.AddUserToGroup("engineering", "user-1", "2025-12-31T23:59:59Z");

        // Assert
        var membership = await _context.UserGroups.FirstOrDefaultAsync(ug => ug.UserId == "user-1");
        membership.Should().NotBeNull();
        membership!.ExpiresAt.Should().NotBeNull();
        membership.ExpiresAt!.Value.Year.Should().Be(2025);
    }

    [Fact]
    public async Task AddUserToGroup_ExistingMembership_UpdatesExpiration()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.AddUserToGroup("engineering", "user-1", "2025-12-31T23:59:59Z");

        // Assert
        result.Should().Contain("Updated membership expiration");
    }

    [Fact]
    public async Task AddUserToGroup_NonExistentGroup_ThrowsException()
    {
        // Arrange
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act & Assert
        var act = async () => await _tools.AddUserToGroup("non-existent", "user-1");

        await act.Should().ThrowAsync<KeyNotFoundException>()
            .WithMessage("*Group*not found*");
    }

    [Fact]
    public async Task AddUserToGroup_NonExistentUser_ThrowsException()
    {
        // Arrange
        await SeedGroupsAsync();
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act & Assert
        var act = async () => await _tools.AddUserToGroup("engineering", "non-existent");

        await act.Should().ThrowAsync<KeyNotFoundException>()
            .WithMessage("*User*not found*");
    }

    // ==================== Remove User from Group Tests ====================

    [Fact]
    public async Task RemoveUserFromGroup_WithValidData_RemovesMembership()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.RemoveUserFromGroup("engineering", "user-1");

        // Assert
        result.Should().Contain("Successfully removed");

        var membership = await _context.UserGroups.FirstOrDefaultAsync(ug => ug.UserId == "user-1");
        membership.Should().BeNull();
    }

    [Fact]
    public async Task RemoveUserFromGroup_NonMember_ThrowsException()
    {
        // Arrange
        await SeedGroupsAsync();
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act & Assert
        var act = async () => await _tools.RemoveUserFromGroup("engineering", "user-1");

        await act.Should().ThrowAsync<KeyNotFoundException>()
            .WithMessage("*not a member*");
    }

    // ==================== Get User Groups Tests ====================

    [Fact]
    public async Task GetUserGroups_ReturnsActiveGroups()
    {
        // Arrange
        await SeedGroupsAsync();
        var group1 = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var group2 = await _context.Groups.FirstAsync(g => g.Code == "sales");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group1.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group2.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.GetUserGroups("user-1");

        // Assert
        result.Should().HaveCount(2);
        result.Should().Contain(g => g.GroupCode == "engineering");
        result.Should().Contain(g => g.GroupCode == "sales");
    }

    [Fact]
    public async Task GetUserGroups_ExcludesInactiveGroups()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        group.IsActive = false;
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            Source = "manual"
        });
        await _context.SaveChangesAsync();
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.GetUserGroups("user-1");

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetUserGroups_ExcludesExpiredMemberships()
    {
        // Arrange
        await SeedGroupsAsync();
        var group = await _context.Groups.FirstAsync(g => g.Code == "engineering");
        var user = new ApplicationUser { Id = "user-1", Email = "user@test.com", UserName = "user@test.com" };
        _context.Users.Add(user);
        _context.UserGroups.Add(new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow.AddDays(-30),
            ExpiresAt = DateTime.UtcNow.AddDays(-1),
            Source = "manual"
        });
        await _context.SaveChangesAsync();
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        // Act
        var result = await _tools.GetUserGroups("user-1");

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetUserGroups_NonExistentUser_ThrowsException()
    {
        // Arrange
        _userManagerMock.Setup(x => x.FindByIdAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);
        _userManagerMock.Setup(x => x.FindByEmailAsync("non-existent")).ReturnsAsync((ApplicationUser?)null);

        // Act & Assert
        var act = async () => await _tools.GetUserGroups("non-existent");

        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    // ==================== Search Users Tests ====================

    [Fact]
    public async Task SearchUsers_FindsByEmail()
    {
        // Arrange
        _context.Users.Add(new ApplicationUser
        {
            Id = "user-1",
            Email = "john.doe@test.com",
            UserName = "john.doe@test.com",
            FullName = "John Doe"
        });
        _context.Users.Add(new ApplicationUser
        {
            Id = "user-2",
            Email = "jane.smith@test.com",
            UserName = "jane.smith@test.com",
            FullName = "Jane Smith"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.SearchUsers("john");

        // Assert
        result.Should().ContainSingle();
        result[0].Email.Should().Be("john.doe@test.com");
    }

    [Fact]
    public async Task SearchUsers_FindsByName()
    {
        // Arrange
        _context.Users.Add(new ApplicationUser
        {
            Id = "user-1",
            Email = "user1@test.com",
            UserName = "user1@test.com",
            FullName = "John Doe"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.SearchUsers("doe");

        // Assert
        result.Should().ContainSingle();
        result[0].FullName.Should().Be("John Doe");
    }

    [Fact]
    public async Task SearchUsers_RespectsLimit()
    {
        // Arrange
        for (int i = 0; i < 30; i++)
        {
            _context.Users.Add(new ApplicationUser
            {
                Id = $"user-{i}",
                Email = $"testuser{i}@test.com",
                UserName = $"testuser{i}@test.com"
            });
        }
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.SearchUsers("testuser", limit: 10);

        // Assert
        result.Should().HaveCount(10);
    }

    [Fact]
    public async Task SearchUsers_ShortQuery_ReturnsEmpty()
    {
        // Arrange
        _context.Users.Add(new ApplicationUser
        {
            Id = "user-1",
            Email = "test@test.com",
            UserName = "test@test.com"
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _tools.SearchUsers("t"); // Too short

        // Assert
        result.Should().BeEmpty();
    }

    // ==================== Helper Methods ====================

    private async Task SeedGroupsAsync()
    {
        _context.Groups.Add(new Group
        {
            Id = Guid.NewGuid(),
            Code = "engineering",
            Name = "Engineering Team",
            Description = "Software engineers",
            IsActive = true,
            Source = "local",
            CreatedAt = DateTime.UtcNow
        });
        _context.Groups.Add(new Group
        {
            Id = Guid.NewGuid(),
            Code = "sales",
            Name = "Sales Team",
            Description = "Sales representatives",
            IsActive = true,
            Source = "local",
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();
    }
}
