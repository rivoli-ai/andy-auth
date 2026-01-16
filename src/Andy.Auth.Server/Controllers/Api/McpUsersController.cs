using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;

namespace Andy.Auth.Server.Controllers.Api;

/// <summary>
/// MCP Tools for user management. These are OAuth-protected endpoints
/// designed to be called by MCP clients (Claude, ChatGPT, VS Code Copilot, etc.)
/// </summary>
[ApiController]
[Route("mcp/tools/users")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Roles = "Admin")]
[Produces("application/json")]
public class McpUsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<McpUsersController> _logger;

    public McpUsersController(
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        ILogger<McpUsersController> logger)
    {
        _userManager = userManager;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// MCP Tool: list_users - List all users
    /// </summary>
    [HttpGet("list")]
    public async Task<IActionResult> ListUsers(
        [FromQuery] int limit = 50,
        [FromQuery] string? search = null)
    {
        var query = _userManager.Users.Where(u => u.DeletedAt == null);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            query = query.Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(searchLower)) ||
                (u.FullName != null && u.FullName.ToLower().Contains(searchLower)));
        }

        var users = await query
            .OrderByDescending(u => u.CreatedAt)
            .Take(Math.Min(limit, 100))
            .ToListAsync();

        var result = new List<object>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            result.Add(new
            {
                user.Id,
                user.Email,
                user.FullName,
                user.IsActive,
                user.IsSuspended,
                Role = roles.FirstOrDefault() ?? "User",
                user.CreatedAt,
                user.LastLoginAt,
                user.MustChangePassword
            });
        }

        return Ok(new { users = result, count = result.Count });
    }

    /// <summary>
    /// MCP Tool: get_user - Get user details by ID or email
    /// </summary>
    [HttpGet("{idOrEmail}")]
    public async Task<IActionResult> GetUser(string idOrEmail)
    {
        ApplicationUser? user;

        // Try to find by ID first, then by email
        user = await _userManager.FindByIdAsync(idOrEmail);
        if (user == null)
        {
            user = await _userManager.FindByEmailAsync(idOrEmail);
        }

        if (user == null || user.DeletedAt.HasValue)
        {
            return NotFound(new { error = "User not found", searched_for = idOrEmail });
        }

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new
        {
            user.Id,
            user.Email,
            user.FullName,
            user.IsActive,
            user.IsSuspended,
            user.SuspensionReason,
            user.ExpiresAt,
            Role = roles.FirstOrDefault() ?? "User",
            user.CreatedAt,
            user.LastLoginAt,
            user.MustChangePassword,
            user.EmailConfirmed,
            user.IsSystemUser
        });
    }

    /// <summary>
    /// MCP Tool: create_user - Create a new user
    /// </summary>
    [HttpPost("create")]
    public async Task<IActionResult> CreateUser([FromBody] McpCreateUserRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { error = "Email and password are required" });
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
                return BadRequest(new { error = "User with this email already exists" });
            }
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FullName = request.FullName ?? request.Email.Split('@')[0],
            EmailConfirmed = true,
            IsActive = true,
            MustChangePassword = request.MustChangePassword,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new { error = "Failed to create user", details = result.Errors.Select(e => e.Description) });
        }

        var role = request.IsAdmin ? "Admin" : "User";
        await _userManager.AddToRoleAsync(user, role);

        await LogAuditAsync("UserCreatedViaMcp", user.Id, user.Email, $"Role: {role}");

        return Ok(new
        {
            success = true,
            message = $"User {request.Email} created successfully",
            user = new { user.Id, user.Email, user.FullName, Role = role, user.MustChangePassword }
        });
    }

    /// <summary>
    /// MCP Tool: suspend_user - Suspend a user
    /// </summary>
    [HttpPost("{idOrEmail}/suspend")]
    public async Task<IActionResult> SuspendUser(string idOrEmail, [FromBody] McpSuspendRequest request)
    {
        var user = await FindUserAsync(idOrEmail);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        if (user.IsSystemUser)
        {
            return BadRequest(new { error = "Cannot suspend system users" });
        }

        user.IsSuspended = true;
        user.SuspensionReason = request.Reason ?? "Suspended via MCP";
        user.SuspendedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await LogAuditAsync("UserSuspendedViaMcp", user.Id, user.Email, $"Reason: {request.Reason}");

        return Ok(new { success = true, message = $"User {user.Email} suspended" });
    }

    /// <summary>
    /// MCP Tool: unsuspend_user - Unsuspend a user
    /// </summary>
    [HttpPost("{idOrEmail}/unsuspend")]
    public async Task<IActionResult> UnsuspendUser(string idOrEmail)
    {
        var user = await FindUserAsync(idOrEmail);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        user.IsSuspended = false;
        user.SuspensionReason = null;
        user.SuspendedAt = null;
        await _userManager.UpdateAsync(user);

        await LogAuditAsync("UserUnsuspendedViaMcp", user.Id, user.Email);

        return Ok(new { success = true, message = $"User {user.Email} unsuspended" });
    }

    /// <summary>
    /// MCP Tool: delete_user - Delete a user (soft delete)
    /// </summary>
    [HttpDelete("{idOrEmail}")]
    public async Task<IActionResult> DeleteUser(string idOrEmail)
    {
        var user = await FindUserAsync(idOrEmail);
        if (user == null)
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

        await LogAuditAsync("UserDeletedViaMcp", user.Id, user.Email);

        return Ok(new { success = true, message = $"User {user.Email} deleted" });
    }

    /// <summary>
    /// MCP Tool: change_role - Change a user's role
    /// </summary>
    [HttpPost("{idOrEmail}/role")]
    public async Task<IActionResult> ChangeRole(string idOrEmail, [FromBody] McpChangeRoleRequest request)
    {
        if (request.Role != "Admin" && request.Role != "User")
        {
            return BadRequest(new { error = "Role must be 'Admin' or 'User'" });
        }

        var user = await FindUserAsync(idOrEmail);
        if (user == null)
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
        var oldRole = currentRoles.FirstOrDefault() ?? "None";

        await _userManager.RemoveFromRolesAsync(user, currentRoles);
        await _userManager.AddToRoleAsync(user, request.Role);

        await LogAuditAsync("UserRoleChangedViaMcp", user.Id, user.Email,
            $"From: {oldRole} To: {request.Role}");

        return Ok(new
        {
            success = true,
            message = $"Role for {user.Email} changed from {oldRole} to {request.Role}"
        });
    }

    /// <summary>
    /// MCP Tool: reset_password - Reset a user's password
    /// </summary>
    [HttpPost("{idOrEmail}/reset-password")]
    public async Task<IActionResult> ResetPassword(string idOrEmail, [FromBody] McpResetPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new { error = "New password is required" });
        }

        var user = await FindUserAsync(idOrEmail);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        // Remove existing password and set new one
        var removeResult = await _userManager.RemovePasswordAsync(user);
        if (!removeResult.Succeeded)
        {
            return BadRequest(new { error = "Failed to reset password", details = removeResult.Errors.Select(e => e.Description) });
        }

        var addResult = await _userManager.AddPasswordAsync(user, request.NewPassword);
        if (!addResult.Succeeded)
        {
            return BadRequest(new { error = "Failed to set new password", details = addResult.Errors.Select(e => e.Description) });
        }

        // Update security stamp to invalidate existing tokens
        await _userManager.UpdateSecurityStampAsync(user);

        // Set MustChangePassword flag
        user.MustChangePassword = request.MustChangePassword;
        await _userManager.UpdateAsync(user);

        await LogAuditAsync("PasswordResetViaMcp", user.Id, user.Email,
            $"MustChangePassword: {request.MustChangePassword}");

        return Ok(new
        {
            success = true,
            message = $"Password reset for {user.Email}",
            must_change_password = request.MustChangePassword
        });
    }

    private async Task<ApplicationUser?> FindUserAsync(string idOrEmail)
    {
        var user = await _userManager.FindByIdAsync(idOrEmail);
        if (user == null)
        {
            user = await _userManager.FindByEmailAsync(idOrEmail);
        }
        if (user?.DeletedAt.HasValue == true)
        {
            return null;
        }
        return user;
    }

    private async Task LogAuditAsync(string action, string? targetUserId, string? targetEmail, string? details = null)
    {
        var currentUserId = User.FindFirst("sub")?.Value ?? "MCP";
        var currentEmail = User.FindFirst("email")?.Value ?? "MCP";
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _auditService.LogAsync(action, currentUserId, currentEmail, targetUserId, targetEmail, details, ipAddress);
    }
}

public class McpCreateUserRequest
{
    public string Email { get; set; } = string.Empty;
    public string? FullName { get; set; }
    public string Password { get; set; } = string.Empty;
    public bool IsAdmin { get; set; } = false;
    public bool MustChangePassword { get; set; } = true;
}

public class McpSuspendRequest
{
    public string? Reason { get; set; }
}

public class McpChangeRoleRequest
{
    public string Role { get; set; } = "User";
}

public class McpResetPasswordRequest
{
    public string NewPassword { get; set; } = string.Empty;
    public bool MustChangePassword { get; set; } = true;
}
