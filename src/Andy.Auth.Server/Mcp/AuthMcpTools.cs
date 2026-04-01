using System.ComponentModel;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ModelContextProtocol.Server;

namespace Andy.Auth.Server.Mcp;

/// <summary>
/// MCP tools for AI assistants to manage users and groups.
/// These tools provide programmatic access to Andy-Auth functionality.
/// </summary>
[McpServerToolType]
public class AuthMcpTools
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AuthMcpTools> _logger;

    public AuthMcpTools(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<AuthMcpTools> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    // ==================== Group Management ====================

    [McpServerTool]
    [Description("List all groups with optional filtering by search term or active status.")]
    public async Task<List<McpGroupInfo>> ListGroups(
        [Description("Optional search term to filter by code, name, or description")] string? search = null,
        [Description("Filter by active status (true/false), or null for all")] bool? isActive = null)
    {
        var query = _context.Groups.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            query = query.Where(g =>
                g.Code.ToLower().Contains(searchLower) ||
                g.Name.ToLower().Contains(searchLower) ||
                (g.Description != null && g.Description.ToLower().Contains(searchLower)));
        }

        if (isActive.HasValue)
        {
            query = query.Where(g => g.IsActive == isActive.Value);
        }

        var now = DateTime.UtcNow;
        var groups = await query
            .OrderBy(g => g.Name)
            .Select(g => new McpGroupInfo(
                g.Id,
                g.Code,
                g.Name,
                g.Description,
                g.IsActive,
                g.Source,
                g.UserGroups.Count(ug => ug.ExpiresAt == null || ug.ExpiresAt > now)))
            .ToListAsync();

        return groups;
    }

    [McpServerTool]
    [Description("Get detailed information about a group by its ID.")]
    public async Task<McpGroupDetail?> GetGroupById(
        [Description("Group ID (GUID)")] string id)
    {
        if (!Guid.TryParse(id, out var groupId))
        {
            throw new ArgumentException($"Invalid group ID format: {id}");
        }

        var group = await _context.Groups
            .AsNoTracking()
            .FirstOrDefaultAsync(g => g.Id == groupId);

        if (group == null)
            return null;

        var now = DateTime.UtcNow;
        var members = await _context.UserGroups
            .AsNoTracking()
            .Where(ug => ug.GroupId == group.Id && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Select(ug => new McpGroupMember(
                ug.UserId,
                ug.User.Email ?? "",
                ug.User.FullName,
                ug.JoinedAt,
                ug.ExpiresAt,
                ug.Source))
            .ToListAsync();

        return new McpGroupDetail(
            group.Id,
            group.Code,
            group.Name,
            group.Description,
            group.IsActive,
            group.Source,
            group.ExternalId,
            group.CreatedAt,
            group.LastSyncedAt,
            members);
    }

    [McpServerTool]
    [Description("Get detailed information about a group by its code.")]
    public async Task<McpGroupDetail?> GetGroup(
        [Description("Group code (e.g., 'engineering')")] string code)
    {
        var group = await _context.Groups
            .AsNoTracking()
            .FirstOrDefaultAsync(g => g.Code == code);

        if (group == null)
            return null;

        var now = DateTime.UtcNow;
        var members = await _context.UserGroups
            .AsNoTracking()
            .Where(ug => ug.GroupId == group.Id && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Select(ug => new McpGroupMember(
                ug.UserId,
                ug.User.Email ?? "",
                ug.User.FullName,
                ug.JoinedAt,
                ug.ExpiresAt,
                ug.Source))
            .ToListAsync();

        return new McpGroupDetail(
            group.Id,
            group.Code,
            group.Name,
            group.Description,
            group.IsActive,
            group.Source,
            group.ExternalId,
            group.CreatedAt,
            group.LastSyncedAt,
            members);
    }

    [McpServerTool]
    [Description("Create a new group.")]
    public async Task<McpGroupInfo> CreateGroup(
        [Description("Unique code for the group (lowercase alphanumeric with hyphens/underscores)")] string code,
        [Description("Display name for the group")] string name,
        [Description("Optional description of the group")] string? description = null)
    {
        // Check for duplicate
        var existing = await _context.Groups.FirstOrDefaultAsync(g => g.Code == code);
        if (existing != null)
        {
            throw new InvalidOperationException($"A group with code '{code}' already exists");
        }

        var group = new Group
        {
            Id = Guid.NewGuid(),
            Code = code,
            Name = name,
            Description = description,
            IsActive = true,
            Source = "local",
            CreatedAt = DateTime.UtcNow
        };

        _context.Groups.Add(group);
        await _context.SaveChangesAsync();

        _logger.LogInformation("MCP: Created group {GroupCode}", code);

        return new McpGroupInfo(group.Id, group.Code, group.Name, group.Description, group.IsActive, group.Source, 0);
    }

    [McpServerTool]
    [Description("Update a group's name, description, or active status.")]
    public async Task<McpGroupInfo> UpdateGroup(
        [Description("Group code to update")] string code,
        [Description("New name (optional)")] string? name = null,
        [Description("New description (optional, use empty string to clear)")] string? description = null,
        [Description("Set active status (optional)")] bool? isActive = null)
    {
        var group = await _context.Groups.FirstOrDefaultAsync(g => g.Code == code);
        if (group == null)
        {
            throw new KeyNotFoundException($"Group with code '{code}' not found");
        }

        if (!string.IsNullOrEmpty(name))
        {
            group.Name = name;
        }

        if (description != null)
        {
            group.Description = description == "" ? null : description;
        }

        if (isActive.HasValue)
        {
            group.IsActive = isActive.Value;
        }

        await _context.SaveChangesAsync();

        _logger.LogInformation("MCP: Updated group {GroupCode}", code);

        var now = DateTime.UtcNow;
        var memberCount = await _context.UserGroups
            .CountAsync(ug => ug.GroupId == group.Id && (ug.ExpiresAt == null || ug.ExpiresAt > now));

        return new McpGroupInfo(group.Id, group.Code, group.Name, group.Description, group.IsActive, group.Source, memberCount);
    }

    [McpServerTool]
    [Description("Delete a locally-created group. Cannot delete groups synced from external sources.")]
    public async Task<string> DeleteGroup(
        [Description("Group code to delete")] string code)
    {
        var group = await _context.Groups.FirstOrDefaultAsync(g => g.Code == code);
        if (group == null)
        {
            throw new KeyNotFoundException($"Group with code '{code}' not found");
        }

        if (group.Source != "local")
        {
            throw new InvalidOperationException("Cannot delete groups synced from external sources");
        }

        // Remove all memberships first
        var memberships = await _context.UserGroups.Where(ug => ug.GroupId == group.Id).ToListAsync();
        _context.UserGroups.RemoveRange(memberships);
        _context.Groups.Remove(group);
        await _context.SaveChangesAsync();

        _logger.LogInformation("MCP: Deleted group {GroupCode}", code);

        return $"Successfully deleted group '{code}' and removed {memberships.Count} memberships";
    }

    // ==================== Group Membership ====================

    [McpServerTool]
    [Description("Add a user to a group.")]
    public async Task<string> AddUserToGroup(
        [Description("Group code")] string groupCode,
        [Description("User ID or email")] string userIdOrEmail,
        [Description("Optional expiration date (ISO 8601 format)")] string? expiresAt = null)
    {
        var group = await _context.Groups.FirstOrDefaultAsync(g => g.Code == groupCode);
        if (group == null)
        {
            throw new KeyNotFoundException($"Group with code '{groupCode}' not found");
        }

        var user = await _userManager.FindByIdAsync(userIdOrEmail);
        if (user == null)
        {
            user = await _userManager.FindByEmailAsync(userIdOrEmail);
        }

        if (user == null)
        {
            throw new KeyNotFoundException($"User '{userIdOrEmail}' not found");
        }

        // Check if already a member
        var existing = await _context.UserGroups
            .FirstOrDefaultAsync(ug => ug.GroupId == group.Id && ug.UserId == user.Id);

        DateTime? expirationDate = null;
        if (!string.IsNullOrEmpty(expiresAt))
        {
            if (!DateTime.TryParse(expiresAt, out var parsed))
            {
                throw new ArgumentException($"Invalid date format for expiresAt: {expiresAt}");
            }
            expirationDate = parsed.ToUniversalTime();
        }

        if (existing != null)
        {
            existing.ExpiresAt = expirationDate;
            await _context.SaveChangesAsync();
            _logger.LogInformation("MCP: Updated membership for {UserId} in group {GroupCode}", user.Id, groupCode);
            return $"Updated membership expiration for user '{user.Email}' in group '{groupCode}'";
        }

        var membership = new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = group.Id,
            JoinedAt = DateTime.UtcNow,
            ExpiresAt = expirationDate,
            Source = "manual"
        };

        _context.UserGroups.Add(membership);
        await _context.SaveChangesAsync();

        _logger.LogInformation("MCP: Added user {UserId} to group {GroupCode}", user.Id, groupCode);

        return $"Successfully added user '{user.Email}' to group '{groupCode}'";
    }

    [McpServerTool]
    [Description("Remove a user from a group.")]
    public async Task<string> RemoveUserFromGroup(
        [Description("Group code")] string groupCode,
        [Description("User ID or email")] string userIdOrEmail)
    {
        var group = await _context.Groups.FirstOrDefaultAsync(g => g.Code == groupCode);
        if (group == null)
        {
            throw new KeyNotFoundException($"Group with code '{groupCode}' not found");
        }

        var user = await _userManager.FindByIdAsync(userIdOrEmail);
        if (user == null)
        {
            user = await _userManager.FindByEmailAsync(userIdOrEmail);
        }

        if (user == null)
        {
            throw new KeyNotFoundException($"User '{userIdOrEmail}' not found");
        }

        var membership = await _context.UserGroups
            .FirstOrDefaultAsync(ug => ug.GroupId == group.Id && ug.UserId == user.Id);

        if (membership == null)
        {
            throw new KeyNotFoundException($"User '{user.Email}' is not a member of group '{groupCode}'");
        }

        _context.UserGroups.Remove(membership);
        await _context.SaveChangesAsync();

        _logger.LogInformation("MCP: Removed user {UserId} from group {GroupCode}", user.Id, groupCode);

        return $"Successfully removed user '{user.Email}' from group '{groupCode}'";
    }

    // ==================== User Information ====================

    [McpServerTool]
    [Description("Get groups for a user.")]
    public async Task<List<McpUserGroupInfo>> GetUserGroups(
        [Description("User ID or email")] string userIdOrEmail)
    {
        var user = await _userManager.FindByIdAsync(userIdOrEmail);
        if (user == null)
        {
            user = await _userManager.FindByEmailAsync(userIdOrEmail);
        }

        if (user == null)
        {
            throw new KeyNotFoundException($"User '{userIdOrEmail}' not found");
        }

        var now = DateTime.UtcNow;
        var groups = await _context.UserGroups
            .AsNoTracking()
            .Where(ug => ug.UserId == user.Id && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Where(ug => ug.Group.IsActive)
            .Select(ug => new McpUserGroupInfo(
                ug.Group.Code,
                ug.Group.Name,
                ug.JoinedAt,
                ug.ExpiresAt,
                ug.Source))
            .ToListAsync();

        return groups;
    }

    [McpServerTool]
    [Description("Search for users by email or name.")]
    public async Task<List<McpUserInfo>> SearchUsers(
        [Description("Search term (email or name)")] string query,
        [Description("Maximum number of results (default: 20)")] int limit = 20)
    {
        if (string.IsNullOrWhiteSpace(query) || query.Length < 2)
        {
            return [];
        }

        var queryLower = query.ToLower();
        var users = await _context.Users
            .AsNoTracking()
            .Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(queryLower)) ||
                (u.FullName != null && u.FullName.ToLower().Contains(queryLower)) ||
                (u.UserName != null && u.UserName.ToLower().Contains(queryLower)))
            .Take(limit)
            .Select(u => new McpUserInfo(
                u.Id,
                u.Email ?? "",
                u.FullName,
                u.UserName,
                u.EmailConfirmed,
                u.TwoFactorEnabled,
                u.LockoutEnd > DateTimeOffset.UtcNow))
            .ToListAsync();

        return users;
    }
}

// ==================== MCP DTOs ====================

public record McpGroupInfo(
    Guid Id,
    string Code,
    string Name,
    string? Description,
    bool IsActive,
    string Source,
    int MemberCount);

public record McpGroupDetail(
    Guid Id,
    string Code,
    string Name,
    string? Description,
    bool IsActive,
    string Source,
    string? ExternalId,
    DateTime CreatedAt,
    DateTime? LastSyncedAt,
    List<McpGroupMember> Members);

public record McpGroupMember(
    string UserId,
    string Email,
    string? FullName,
    DateTime JoinedAt,
    DateTime? ExpiresAt,
    string Source);

public record McpUserGroupInfo(
    string GroupCode,
    string GroupName,
    DateTime JoinedAt,
    DateTime? ExpiresAt,
    string Source);

public record McpUserInfo(
    string Id,
    string Email,
    string? FullName,
    string? UserName,
    bool EmailConfirmed,
    bool TwoFactorEnabled,
    bool IsLockedOut);
