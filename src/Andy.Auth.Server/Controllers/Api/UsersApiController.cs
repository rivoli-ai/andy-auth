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
/// REST API endpoints for user management.
/// Requires OAuth bearer token with Admin role.
/// </summary>
[ApiController]
[Route("api/users")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Roles = "Admin")]
[Produces("application/json")]
public class UsersApiController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<UsersApiController> _logger;

    public UsersApiController(
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        ILogger<UsersApiController> logger)
    {
        _userManager = userManager;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// List all users with optional filtering and pagination.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(UserListResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> ListUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null,
        [FromQuery] bool? isActive = null)
    {
        var query = _userManager.Users.Where(u => u.DeletedAt == null);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            query = query.Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(searchLower)) ||
                (u.FullName != null && u.FullName.ToLower().Contains(searchLower)));
        }

        if (isActive.HasValue)
        {
            query = query.Where(u => u.IsActive == isActive.Value);
        }

        var total = await query.CountAsync();
        var users = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var userDtos = new List<UserDto>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            userDtos.Add(MapToDto(user, roles));
        }

        return Ok(new UserListResponse
        {
            Users = userDtos,
            Total = total,
            Page = page,
            PageSize = pageSize
        });
    }

    /// <summary>
    /// Get a specific user by ID.
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found" });
        }

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(MapToDto(user, roles));
    }

    /// <summary>
    /// Create a new user.
    /// </summary>
    [HttpPost]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(object), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            // If the user was soft-deleted, hard-delete them to allow email reuse
            if (existingUser.DeletedAt.HasValue)
            {
                await _userManager.DeleteAsync(existingUser);
            }
            else
            {
                return BadRequest(new { error = "A user with this email already exists" });
            }
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FullName = request.FullName,
            EmailConfirmed = true,
            IsActive = true,
            MustChangePassword = request.MustChangePassword,
            ExpiresAt = request.ExpiresAt,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        var role = request.IsAdmin ? "Admin" : "User";
        await _userManager.AddToRoleAsync(user, role);

        await LogAuditAsync("UserCreatedViaApi", user.Id, user.Email,
            $"Role: {role}, MustChangePassword: {request.MustChangePassword}");

        var roles = await _userManager.GetRolesAsync(user);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, MapToDto(user, roles));
    }

    /// <summary>
    /// Update an existing user.
    /// </summary>
    [HttpPut("{id}")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserRequest request)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found" });
        }

        if (!string.IsNullOrEmpty(request.FullName))
        {
            user.FullName = request.FullName;
        }

        if (request.IsActive.HasValue)
        {
            user.IsActive = request.IsActive.Value;
        }

        if (request.ExpiresAt.HasValue)
        {
            user.ExpiresAt = request.ExpiresAt;
        }

        await _userManager.UpdateAsync(user);
        await LogAuditAsync("UserUpdatedViaApi", user.Id, user.Email);

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(MapToDto(user, roles));
    }

    /// <summary>
    /// Delete a user (soft delete).
    /// </summary>
    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found" });
        }

        if (user.IsSystemUser)
        {
            return BadRequest(new { error = "Cannot delete system users" });
        }

        // Prevent self-deletion
        var currentUserId = User.FindFirst("sub")?.Value;
        if (user.Id == currentUserId)
        {
            return BadRequest(new { error = "You cannot delete your own account" });
        }

        user.DeletedAt = DateTime.UtcNow;
        user.IsActive = false;
        await _userManager.UpdateAsync(user);

        await LogAuditAsync("UserDeletedViaApi", user.Id, user.Email);
        return NoContent();
    }

    /// <summary>
    /// Suspend a user.
    /// </summary>
    [HttpPost("{id}/suspend")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> SuspendUser(string id, [FromBody] SuspendUserRequest request)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found" });
        }

        user.IsSuspended = true;
        user.SuspensionReason = request.Reason;
        user.SuspendedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await LogAuditAsync("UserSuspendedViaApi", user.Id, user.Email, $"Reason: {request.Reason}");

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(MapToDto(user, roles));
    }

    /// <summary>
    /// Unsuspend a user.
    /// </summary>
    [HttpPost("{id}/unsuspend")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UnsuspendUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found" });
        }

        user.IsSuspended = false;
        user.SuspensionReason = null;
        user.SuspendedAt = null;
        await _userManager.UpdateAsync(user);

        await LogAuditAsync("UserUnsuspendedViaApi", user.Id, user.Email);

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(MapToDto(user, roles));
    }

    /// <summary>
    /// Change a user's role.
    /// </summary>
    [HttpPost("{id}/roles")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ChangeRole(string id, [FromBody] ChangeRoleRequest request)
    {
        if (request.Role != "Admin" && request.Role != "User")
        {
            return BadRequest(new { error = "Invalid role. Must be 'Admin' or 'User'" });
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found" });
        }

        // Prevent demoting the last admin
        if (request.Role == "User" && await _userManager.IsInRoleAsync(user, "Admin"))
        {
            var adminCount = (await _userManager.GetUsersInRoleAsync("Admin")).Count;
            if (adminCount <= 1)
            {
                return BadRequest(new { error = "Cannot demote the last admin user" });
            }
        }

        var currentRoles = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, currentRoles);
        await _userManager.AddToRoleAsync(user, request.Role);

        await LogAuditAsync("UserRoleChangedViaApi", user.Id, user.Email,
            $"From: {string.Join(",", currentRoles)} To: {request.Role}");

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(MapToDto(user, roles));
    }

    private static UserDto MapToDto(ApplicationUser user, IList<string> roles)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email ?? "",
            FullName = user.FullName,
            IsActive = user.IsActive,
            IsSuspended = user.IsSuspended,
            SuspensionReason = user.SuspensionReason,
            ExpiresAt = user.ExpiresAt,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt,
            Roles = roles.ToList(),
            MustChangePassword = user.MustChangePassword
        };
    }

    private async Task LogAuditAsync(string action, string? targetUserId, string? targetEmail, string? details = null)
    {
        var currentUserId = User.FindFirst("sub")?.Value ?? "API";
        var currentEmail = User.FindFirst("email")?.Value ?? "API";
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _auditService.LogAsync(action, currentUserId, currentEmail, targetUserId, targetEmail, details, ipAddress);
    }
}

// DTOs
public class UserListResponse
{
    public List<UserDto> Users { get; set; } = new();
    public int Total { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
}

public class UserDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FullName { get; set; }
    public bool IsActive { get; set; }
    public bool IsSuspended { get; set; }
    public string? SuspensionReason { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public List<string> Roles { get; set; } = new();
    public bool MustChangePassword { get; set; }
}

public class CreateUserRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string FullName { get; set; } = string.Empty;

    [Required]
    [MinLength(8)]
    public string Password { get; set; } = string.Empty;

    public bool IsAdmin { get; set; } = false;
    public bool MustChangePassword { get; set; } = true;
    public DateTime? ExpiresAt { get; set; }
}

public class UpdateUserRequest
{
    public string? FullName { get; set; }
    public bool? IsActive { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

public class SuspendUserRequest
{
    public string Reason { get; set; } = string.Empty;
}

public class ChangeRoleRequest
{
    [Required]
    public string Role { get; set; } = "User";
}
