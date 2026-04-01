using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using System.ComponentModel.DataAnnotations;

namespace Andy.Auth.Server.Controllers.Api;

/// <summary>
/// REST API endpoints for group management.
/// Requires OAuth bearer token with Admin role.
/// </summary>
[ApiController]
[Route("api/groups")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Roles = "Admin")]
[Produces("application/json")]
public class GroupsApiController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<GroupsApiController> _logger;

    public GroupsApiController(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        ILogger<GroupsApiController> logger)
    {
        _context = context;
        _userManager = userManager;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// List all groups with optional filtering.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(GroupListResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> ListGroups(
        [FromQuery] string? search = null,
        [FromQuery] bool? isActive = null)
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

        var groups = await query
            .OrderBy(g => g.Name)
            .Select(g => new GroupDto
            {
                Id = g.Id,
                Code = g.Code,
                Name = g.Name,
                Description = g.Description,
                IsActive = g.IsActive,
                Source = g.Source,
                ExternalId = g.ExternalId,
                MemberCount = g.UserGroups.Count(ug => ug.ExpiresAt == null || ug.ExpiresAt > DateTime.UtcNow),
                CreatedAt = g.CreatedAt,
                LastSyncedAt = g.LastSyncedAt
            })
            .ToListAsync();

        return Ok(new GroupListResponse { Groups = groups });
    }

    /// <summary>
    /// Get a specific group by ID.
    /// </summary>
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(GroupDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetGroup(Guid id)
    {
        var group = await _context.Groups
            .AsNoTracking()
            .Where(g => g.Id == id)
            .Select(g => new GroupDetailDto
            {
                Id = g.Id,
                Code = g.Code,
                Name = g.Name,
                Description = g.Description,
                IsActive = g.IsActive,
                Source = g.Source,
                ExternalId = g.ExternalId,
                CreatedAt = g.CreatedAt,
                LastSyncedAt = g.LastSyncedAt
            })
            .FirstOrDefaultAsync();

        if (group == null)
        {
            return NotFound(new { error = "Group not found" });
        }

        // Load members separately
        var now = DateTime.UtcNow;
        group.Members = await _context.UserGroups
            .AsNoTracking()
            .Where(ug => ug.GroupId == id && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Select(ug => new GroupMemberDto
            {
                UserId = ug.UserId,
                Email = ug.User.Email ?? "",
                FullName = ug.User.FullName,
                JoinedAt = ug.JoinedAt,
                ExpiresAt = ug.ExpiresAt,
                Source = ug.Source
            })
            .ToListAsync();

        return Ok(group);
    }

    /// <summary>
    /// Get a group by code.
    /// </summary>
    [HttpGet("by-code/{code}")]
    [ProducesResponseType(typeof(GroupDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetGroupByCode(string code)
    {
        var group = await _context.Groups
            .AsNoTracking()
            .Where(g => g.Code == code)
            .Select(g => new GroupDetailDto
            {
                Id = g.Id,
                Code = g.Code,
                Name = g.Name,
                Description = g.Description,
                IsActive = g.IsActive,
                Source = g.Source,
                ExternalId = g.ExternalId,
                CreatedAt = g.CreatedAt,
                LastSyncedAt = g.LastSyncedAt
            })
            .FirstOrDefaultAsync();

        if (group == null)
        {
            return NotFound(new { error = "Group not found" });
        }

        var now = DateTime.UtcNow;
        group.Members = await _context.UserGroups
            .AsNoTracking()
            .Where(ug => ug.GroupId == group.Id && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Select(ug => new GroupMemberDto
            {
                UserId = ug.UserId,
                Email = ug.User.Email ?? "",
                FullName = ug.User.FullName,
                JoinedAt = ug.JoinedAt,
                ExpiresAt = ug.ExpiresAt,
                Source = ug.Source
            })
            .ToListAsync();

        return Ok(group);
    }

    /// <summary>
    /// Create a new group.
    /// </summary>
    [HttpPost]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(object), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateGroup([FromBody] CreateGroupRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Check for duplicate code
        var existingGroup = await _context.Groups
            .FirstOrDefaultAsync(g => g.Code == request.Code);
        if (existingGroup != null)
        {
            return BadRequest(new { error = "A group with this code already exists" });
        }

        var group = new Group
        {
            Id = Guid.NewGuid(),
            Code = request.Code,
            Name = request.Name,
            Description = request.Description,
            IsActive = true,
            Source = "local",
            CreatedAt = DateTime.UtcNow
        };

        _context.Groups.Add(group);
        await _context.SaveChangesAsync();

        await LogAuditAsync("GroupCreated", group.Id.ToString(), group.Code);
        _logger.LogInformation("Group created: {GroupCode}", group.Code);

        return CreatedAtAction(nameof(GetGroup), new { id = group.Id }, new GroupDto
        {
            Id = group.Id,
            Code = group.Code,
            Name = group.Name,
            Description = group.Description,
            IsActive = group.IsActive,
            Source = group.Source,
            MemberCount = 0,
            CreatedAt = group.CreatedAt
        });
    }

    /// <summary>
    /// Update a group.
    /// </summary>
    [HttpPut("{id:guid}")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateGroup(Guid id, [FromBody] UpdateGroupRequest request)
    {
        var group = await _context.Groups.FindAsync(id);
        if (group == null)
        {
            return NotFound(new { error = "Group not found" });
        }

        if (!string.IsNullOrEmpty(request.Name))
        {
            group.Name = request.Name;
        }

        if (request.Description != null)
        {
            group.Description = request.Description;
        }

        if (request.IsActive.HasValue)
        {
            group.IsActive = request.IsActive.Value;
        }

        await _context.SaveChangesAsync();
        await LogAuditAsync("GroupUpdated", group.Id.ToString(), group.Code);

        var memberCount = await _context.UserGroups
            .CountAsync(ug => ug.GroupId == id && (ug.ExpiresAt == null || ug.ExpiresAt > DateTime.UtcNow));

        return Ok(new GroupDto
        {
            Id = group.Id,
            Code = group.Code,
            Name = group.Name,
            Description = group.Description,
            IsActive = group.IsActive,
            Source = group.Source,
            MemberCount = memberCount,
            CreatedAt = group.CreatedAt,
            LastSyncedAt = group.LastSyncedAt
        });
    }

    /// <summary>
    /// Delete a group.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> DeleteGroup(Guid id)
    {
        var group = await _context.Groups.FindAsync(id);
        if (group == null)
        {
            return NotFound(new { error = "Group not found" });
        }

        if (group.Source != "local")
        {
            return BadRequest(new { error = "Cannot delete groups synced from external sources" });
        }

        // Remove all memberships first
        var memberships = await _context.UserGroups.Where(ug => ug.GroupId == id).ToListAsync();
        _context.UserGroups.RemoveRange(memberships);
        _context.Groups.Remove(group);
        await _context.SaveChangesAsync();

        await LogAuditAsync("GroupDeleted", group.Id.ToString(), group.Code);
        _logger.LogInformation("Group deleted: {GroupCode}", group.Code);

        return NoContent();
    }

    /// <summary>
    /// Add a user to a group.
    /// </summary>
    [HttpPost("{id:guid}/members")]
    [ProducesResponseType(typeof(GroupMemberDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> AddMember(Guid id, [FromBody] AddMemberRequest request)
    {
        var group = await _context.Groups.FindAsync(id);
        if (group == null)
        {
            return NotFound(new { error = "Group not found" });
        }

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null)
        {
            // Try to find by email
            user = await _userManager.FindByEmailAsync(request.UserId);
        }

        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        // Check if already a member
        var existingMembership = await _context.UserGroups
            .FirstOrDefaultAsync(ug => ug.GroupId == id && ug.UserId == user.Id);

        if (existingMembership != null)
        {
            // Update expiration if provided
            if (request.ExpiresAt.HasValue)
            {
                existingMembership.ExpiresAt = request.ExpiresAt;
                await _context.SaveChangesAsync();
            }
            return Ok(new GroupMemberDto
            {
                UserId = user.Id,
                Email = user.Email ?? "",
                FullName = user.FullName,
                JoinedAt = existingMembership.JoinedAt,
                ExpiresAt = existingMembership.ExpiresAt,
                Source = existingMembership.Source
            });
        }

        var membership = new UserGroup
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            GroupId = id,
            JoinedAt = DateTime.UtcNow,
            ExpiresAt = request.ExpiresAt,
            Source = "manual"
        };

        _context.UserGroups.Add(membership);
        await _context.SaveChangesAsync();

        await LogAuditAsync("UserAddedToGroup", user.Id, user.Email, $"Group: {group.Code}");
        _logger.LogInformation("User {UserId} added to group {GroupCode}", user.Id, group.Code);

        return CreatedAtAction(nameof(GetGroup), new { id = group.Id }, new GroupMemberDto
        {
            UserId = user.Id,
            Email = user.Email ?? "",
            FullName = user.FullName,
            JoinedAt = membership.JoinedAt,
            ExpiresAt = membership.ExpiresAt,
            Source = membership.Source
        });
    }

    /// <summary>
    /// Remove a user from a group.
    /// </summary>
    [HttpDelete("{id:guid}/members/{userId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveMember(Guid id, string userId)
    {
        var membership = await _context.UserGroups
            .Include(ug => ug.Group)
            .Include(ug => ug.User)
            .FirstOrDefaultAsync(ug => ug.GroupId == id && ug.UserId == userId);

        if (membership == null)
        {
            return NotFound(new { error = "Membership not found" });
        }

        _context.UserGroups.Remove(membership);
        await _context.SaveChangesAsync();

        await LogAuditAsync("UserRemovedFromGroup", userId, membership.User.Email, $"Group: {membership.Group.Code}");
        _logger.LogInformation("User {UserId} removed from group {GroupCode}", userId, membership.Group.Code);

        return NoContent();
    }

    /// <summary>
    /// Get groups for a specific user.
    /// </summary>
    [HttpGet("for-user/{userId}")]
    [ProducesResponseType(typeof(List<GroupDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetGroupsForUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        var now = DateTime.UtcNow;
        var groups = await _context.UserGroups
            .AsNoTracking()
            .Where(ug => ug.UserId == userId && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Where(ug => ug.Group.IsActive)
            .Select(ug => new GroupDto
            {
                Id = ug.Group.Id,
                Code = ug.Group.Code,
                Name = ug.Group.Name,
                Description = ug.Group.Description,
                IsActive = ug.Group.IsActive,
                Source = ug.Group.Source,
                CreatedAt = ug.Group.CreatedAt
            })
            .ToListAsync();

        return Ok(groups);
    }

    private async Task LogAuditAsync(string action, string? targetId, string? targetName, string? details = null)
    {
        var currentUserId = User.FindFirst("sub")?.Value ?? "API";
        var currentEmail = User.FindFirst("email")?.Value ?? "API";
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _auditService.LogAsync(action, currentUserId, currentEmail, targetId, targetName, details, ipAddress);
    }
}

// DTOs
public class GroupListResponse
{
    public List<GroupDto> Groups { get; set; } = new();
}

public class GroupDto
{
    public Guid Id { get; set; }
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; }
    public string Source { get; set; } = "local";
    public string? ExternalId { get; set; }
    public int MemberCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastSyncedAt { get; set; }
}

public class GroupDetailDto : GroupDto
{
    public List<GroupMemberDto> Members { get; set; } = new();
}

public class GroupMemberDto
{
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FullName { get; set; }
    public DateTime JoinedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string Source { get; set; } = "manual";
}

public class CreateGroupRequest
{
    [Required]
    [StringLength(100, MinimumLength = 2)]
    [RegularExpression(@"^[a-z0-9\-_]+$", ErrorMessage = "Code must be lowercase alphanumeric with hyphens or underscores")]
    public string Code { get; set; } = string.Empty;

    [Required]
    [StringLength(200, MinimumLength = 2)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }
}

public class UpdateGroupRequest
{
    [StringLength(200, MinimumLength = 2)]
    public string? Name { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    public bool? IsActive { get; set; }
}

public class AddMemberRequest
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    public DateTime? ExpiresAt { get; set; }
}
