using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Controllers;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictTokenManager tokenManager,
        IOpenIddictAuthorizationManager authorizationManager,
        ILogger<AdminController> logger)
    {
        _context = context;
        _userManager = userManager;
        _applicationManager = applicationManager;
        _tokenManager = tokenManager;
        _authorizationManager = authorizationManager;
        _logger = logger;
    }

    public async Task<IActionResult> Index()
    {
        // Count OAuth clients
        int clientCount = 0;
        await foreach (var _ in _applicationManager.ListAsync())
        {
            clientCount++;
        }

        var stats = new
        {
            TotalUsers = await _userManager.Users.CountAsync(),
            ActiveUsers = await _userManager.Users.Where(u => u.IsActive).CountAsync(),
            TotalClients = clientCount,
            RecentLogins = await _userManager.Users
                .Where(u => u.LastLoginAt != null)
                .OrderByDescending(u => u.LastLoginAt)
                .Take(5)
                .Select(u => new { u.Email, u.LastLoginAt })
                .ToListAsync()
        };

        ViewBag.Stats = stats;
        return View();
    }

    public async Task<IActionResult> Clients()
    {
        var clients = new List<ClientViewModel>();

        // Get all OpenIddict applications
        await foreach (var application in _applicationManager.ListAsync())
        {
            var clientId = await _applicationManager.GetClientIdAsync(application);
            var displayName = await _applicationManager.GetDisplayNameAsync(application);
            var redirectUris = await _applicationManager.GetRedirectUrisAsync(application);

            clients.Add(new ClientViewModel
            {
                ClientId = clientId ?? "Unknown",
                DisplayName = displayName ?? "Unknown",
                RedirectUris = redirectUris.Select(uri => uri.ToString()).ToList()
            });
        }

        return View(clients);
    }

    public async Task<IActionResult> Users(int page = 1, int pageSize = 20, string? search = null, string sortBy = "CreatedAt", string sortOrder = "desc")
    {
        // Start with all users
        var query = _userManager.Users.AsQueryable();

        // Apply search filter
        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            query = query.Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(searchLower)) ||
                (u.FullName != null && u.FullName.ToLower().Contains(searchLower))
            );
        }

        // Apply sorting
        query = sortBy switch
        {
            "Email" => sortOrder == "asc" ? query.OrderBy(u => u.Email) : query.OrderByDescending(u => u.Email),
            "FullName" => sortOrder == "asc" ? query.OrderBy(u => u.FullName) : query.OrderByDescending(u => u.FullName),
            "LastLogin" => sortOrder == "asc" ? query.OrderBy(u => u.LastLoginAt) : query.OrderByDescending(u => u.LastLoginAt),
            "CreatedAt" => sortOrder == "asc" ? query.OrderBy(u => u.CreatedAt) : query.OrderByDescending(u => u.CreatedAt),
            _ => query.OrderByDescending(u => u.CreatedAt)
        };

        var totalUsers = await query.CountAsync();
        var users = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        // Get roles for each user
        var usersWithRoles = new List<(ApplicationUser User, bool IsAdmin)>();
        foreach (var user in users)
        {
            var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
            usersWithRoles.Add((user, isAdmin));
        }

        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalUsers / (double)pageSize);
        ViewBag.TotalUsers = totalUsers;
        ViewBag.Search = search;
        ViewBag.SortBy = sortBy;
        ViewBag.SortOrder = sortOrder;

        return View(usersWithRoles);
    }

    [HttpPost]
    public async Task<IActionResult> SuspendUser(string userId, string reason)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        user.IsSuspended = true;
        user.SuspensionReason = reason;
        user.SuspendedAt = DateTime.UtcNow;

        await _userManager.UpdateAsync(user);
        await LogAuditAsync("UserSuspended", user.Id, user.Email, $"Reason: {reason}");

        TempData["SuccessMessage"] = $"User {user.Email} has been suspended.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> UnsuspendUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        user.IsSuspended = false;
        user.SuspensionReason = null;
        user.SuspendedAt = null;

        await _userManager.UpdateAsync(user);
        await LogAuditAsync("UserUnsuspended", user.Id, user.Email);

        TempData["SuccessMessage"] = $"User {user.Email} has been unsuspended.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> SetExpiration(string userId, DateTime? expiresAt)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        user.ExpiresAt = expiresAt;

        await _userManager.UpdateAsync(user);

        var details = expiresAt.HasValue
            ? $"Expires: {expiresAt.Value:yyyy-MM-dd HH:mm}"
            : "Expiration removed";
        await LogAuditAsync("UserExpirationSet", user.Id, user.Email, details);

        TempData["SuccessMessage"] = expiresAt.HasValue
            ? $"Expiration date set for {user.Email}."
            : $"Expiration date removed for {user.Email}.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> DeleteUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        // Prevent deletion of system users
        if (user.IsSystemUser)
        {
            TempData["ErrorMessage"] = $"Cannot delete system user {user.Email}. System users are protected from deletion.";
            return RedirectToAction(nameof(Users));
        }

        // Soft delete
        user.DeletedAt = DateTime.UtcNow;
        user.IsActive = false;

        await _userManager.UpdateAsync(user);
        await LogAuditAsync("UserDeleted", user.Id, user.Email);

        TempData["SuccessMessage"] = $"User {user.Email} has been deleted.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> UpdateUserName(string userId, string newName)
    {
        if (string.IsNullOrWhiteSpace(newName))
        {
            TempData["ErrorMessage"] = "Name cannot be empty.";
            return RedirectToAction(nameof(Users));
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        var oldName = user.FullName;
        user.FullName = newName.Trim();

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            TempData["ErrorMessage"] = $"Failed to update name: {errors}";
            return RedirectToAction(nameof(Users));
        }

        await LogAuditAsync("UserNameUpdated", user.Id, user.Email, $"Name changed from '{oldName}' to '{newName}'");

        TempData["SuccessMessage"] = $"Name updated successfully for {user.Email}.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> ResetPassword(string userId, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            TempData["ErrorMessage"] = "Password cannot be empty.";
            return RedirectToAction(nameof(Users));
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        // Validate password strength
        var passwordValidator = new PasswordValidator<ApplicationUser>();
        var validationResult = await passwordValidator.ValidateAsync(_userManager, user, newPassword);

        if (!validationResult.Succeeded)
        {
            var errors = string.Join(", ", validationResult.Errors.Select(e => e.Description));
            TempData["ErrorMessage"] = $"Password validation failed: {errors}";
            return RedirectToAction(nameof(Users));
        }

        // Remove existing password and set new one
        var removeResult = await _userManager.RemovePasswordAsync(user);
        if (!removeResult.Succeeded)
        {
            var errors = string.Join(", ", removeResult.Errors.Select(e => e.Description));
            TempData["ErrorMessage"] = $"Failed to reset password: {errors}";
            return RedirectToAction(nameof(Users));
        }

        var addResult = await _userManager.AddPasswordAsync(user, newPassword);
        if (!addResult.Succeeded)
        {
            var errors = string.Join(", ", addResult.Errors.Select(e => e.Description));
            TempData["ErrorMessage"] = $"Failed to set new password: {errors}";
            return RedirectToAction(nameof(Users));
        }

        // Update security stamp to invalidate existing tokens
        await _userManager.UpdateSecurityStampAsync(user);

        await LogAuditAsync("PasswordReset", user.Id, user.Email, "Password reset by admin");

        TempData["SuccessMessage"] = $"Password reset successfully for {user.Email}.";
        return RedirectToAction(nameof(Users));
    }

    public async Task<IActionResult> AuditLogs(int page = 1, int pageSize = 50, string? search = null, string? action = null, string sortBy = "PerformedAt", string sortOrder = "desc")
    {
        // Start with all audit logs
        var query = _context.AuditLogs.AsQueryable();

        // Apply search filter (email or details)
        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            query = query.Where(l =>
                (l.PerformedByEmail != null && l.PerformedByEmail.ToLower().Contains(searchLower)) ||
                (l.TargetUserEmail != null && l.TargetUserEmail.ToLower().Contains(searchLower)) ||
                (l.Details != null && l.Details.ToLower().Contains(searchLower))
            );
        }

        // Apply action filter
        if (!string.IsNullOrWhiteSpace(action))
        {
            query = query.Where(l => l.Action == action);
        }

        // Apply sorting
        query = sortBy switch
        {
            "Action" => sortOrder == "asc" ? query.OrderBy(l => l.Action) : query.OrderByDescending(l => l.Action),
            "PerformedByEmail" => sortOrder == "asc" ? query.OrderBy(l => l.PerformedByEmail) : query.OrderByDescending(l => l.PerformedByEmail),
            "TargetUserEmail" => sortOrder == "asc" ? query.OrderBy(l => l.TargetUserEmail) : query.OrderByDescending(l => l.TargetUserEmail),
            "PerformedAt" => sortOrder == "asc" ? query.OrderBy(l => l.PerformedAt) : query.OrderByDescending(l => l.PerformedAt),
            _ => query.OrderByDescending(l => l.PerformedAt)
        };

        var totalLogs = await query.CountAsync();
        var logs = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        // Get distinct actions for filter dropdown
        var distinctActions = await _context.AuditLogs
            .Select(l => l.Action)
            .Distinct()
            .OrderBy(a => a)
            .ToListAsync();

        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalLogs / (double)pageSize);
        ViewBag.TotalLogs = totalLogs;
        ViewBag.Search = search;
        ViewBag.Action = action;
        ViewBag.SortBy = sortBy;
        ViewBag.SortOrder = sortOrder;
        ViewBag.DistinctActions = distinctActions;

        return View(logs);
    }

    public async Task<IActionResult> Tokens(int page = 1, int pageSize = 50, string? search = null, string? status = null)
    {
        var tokens = new List<TokenViewModel>();
        var allTokens = new List<TokenViewModel>();

        // Collect all tokens
        await foreach (var token in _tokenManager.ListAsync())
        {
            var tokenId = await _tokenManager.GetIdAsync(token);
            var subject = await _tokenManager.GetSubjectAsync(token);
            var applicationId = await _tokenManager.GetApplicationIdAsync(token);
            var createdAt = await _tokenManager.GetCreationDateAsync(token);
            var expiresAt = await _tokenManager.GetExpirationDateAsync(token);
            var tokenStatus = await _tokenManager.GetStatusAsync(token);
            var tokenType = await _tokenManager.GetTypeAsync(token);

            // Get application name
            string? applicationName = null;
            if (!string.IsNullOrEmpty(applicationId))
            {
                var app = await _applicationManager.FindByIdAsync(applicationId);
                if (app != null)
                {
                    applicationName = await _applicationManager.GetDisplayNameAsync(app);
                }
            }

            // Get user email
            string? userEmail = null;
            if (!string.IsNullOrEmpty(subject))
            {
                var user = await _userManager.FindByIdAsync(subject);
                if (user != null)
                {
                    userEmail = user.Email;
                }
            }

            allTokens.Add(new TokenViewModel
            {
                Id = tokenId ?? "",
                Subject = subject,
                UserEmail = userEmail,
                ApplicationId = applicationId,
                ApplicationName = applicationName,
                CreatedAt = createdAt?.DateTime,
                ExpiresAt = expiresAt?.DateTime,
                Status = tokenStatus ?? "Unknown",
                Type = tokenType ?? "Unknown"
            });
        }

        // Apply filters
        var filtered = allTokens.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            filtered = filtered.Where(t =>
                (t.UserEmail != null && t.UserEmail.ToLower().Contains(searchLower)) ||
                (t.ApplicationName != null && t.ApplicationName.ToLower().Contains(searchLower)) ||
                (t.Subject != null && t.Subject.ToLower().Contains(searchLower))
            );
        }

        if (!string.IsNullOrWhiteSpace(status))
        {
            filtered = filtered.Where(t => t.Status.Equals(status, StringComparison.OrdinalIgnoreCase));
        }

        // Sort by creation date descending
        var sortedTokens = filtered.OrderByDescending(t => t.CreatedAt).ToList();

        // Apply pagination
        var totalTokens = sortedTokens.Count;
        tokens = sortedTokens.Skip((page - 1) * pageSize).Take(pageSize).ToList();

        // Calculate statistics
        var stats = new TokenStatsViewModel
        {
            TotalTokens = allTokens.Count,
            ActiveTokens = allTokens.Count(t => t.Status.Equals("valid", StringComparison.OrdinalIgnoreCase)),
            ExpiredTokens = allTokens.Count(t => t.ExpiresAt.HasValue && t.ExpiresAt < DateTime.UtcNow),
            RevokedTokens = allTokens.Count(t => t.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ||
                                                  t.Status.Equals("redeemed", StringComparison.OrdinalIgnoreCase))
        };

        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalTokens / (double)pageSize);
        ViewBag.TotalTokens = totalTokens;
        ViewBag.Search = search;
        ViewBag.Status = status;
        ViewBag.Stats = stats;

        return View(tokens);
    }

    [HttpPost]
    public async Task<IActionResult> RevokeToken(string tokenId)
    {
        var token = await _tokenManager.FindByIdAsync(tokenId);
        if (token == null)
        {
            TempData["ErrorMessage"] = "Token not found.";
            return RedirectToAction(nameof(Tokens));
        }

        var subject = await _tokenManager.GetSubjectAsync(token);
        string? userEmail = null;
        if (!string.IsNullOrEmpty(subject))
        {
            var user = await _userManager.FindByIdAsync(subject);
            userEmail = user?.Email;
        }

        try
        {
            await _tokenManager.TryRevokeAsync(token);
            await LogAuditAsync("TokenRevoked", subject, userEmail, $"Token ID: {tokenId}");
            TempData["SuccessMessage"] = "Token has been revoked.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke token {TokenId}", tokenId);
            TempData["ErrorMessage"] = "Failed to revoke token.";
        }

        return RedirectToAction(nameof(Tokens));
    }

    [HttpPost]
    public async Task<IActionResult> RevokeUserTokens(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            TempData["ErrorMessage"] = "User not found.";
            return RedirectToAction(nameof(Users));
        }

        var revokedCount = 0;

        // Find and revoke all tokens for this user
        await foreach (var token in _tokenManager.FindBySubjectAsync(userId))
        {
            try
            {
                await _tokenManager.TryRevokeAsync(token);
                revokedCount++;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke token for user {UserId}", userId);
            }
        }

        await LogAuditAsync("UserTokensRevoked", userId, user.Email, $"Revoked {revokedCount} tokens");
        TempData["SuccessMessage"] = $"Revoked {revokedCount} tokens for {user.Email}.";

        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> RevokeAllTokens()
    {
        var revokedCount = 0;

        await foreach (var token in _tokenManager.ListAsync())
        {
            var status = await _tokenManager.GetStatusAsync(token);
            if (status?.Equals("valid", StringComparison.OrdinalIgnoreCase) == true)
            {
                try
                {
                    await _tokenManager.TryRevokeAsync(token);
                    revokedCount++;
                }
                catch (Exception ex)
                {
                    var tokenId = await _tokenManager.GetIdAsync(token);
                    _logger.LogError(ex, "Failed to revoke token {TokenId}", tokenId);
                }
            }
        }

        await LogAuditAsync("AllTokensRevoked", null, null, $"Revoked {revokedCount} tokens");
        TempData["SuccessMessage"] = $"Revoked {revokedCount} active tokens.";

        return RedirectToAction(nameof(Tokens));
    }

    private async Task LogAuditAsync(string action, string? targetUserId = null, string? targetUserEmail = null, string? details = null)
    {
        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null)
            return;

        var auditLog = new AuditLog
        {
            Action = action,
            PerformedById = currentUser.Id,
            PerformedByEmail = currentUser.Email ?? "Unknown",
            TargetUserId = targetUserId,
            TargetUserEmail = targetUserEmail,
            Details = details,
            PerformedAt = DateTime.UtcNow,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();
    }

    public class ClientViewModel
    {
        public string ClientId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public List<string> RedirectUris { get; set; } = new();
    }

    public class TokenViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string? Subject { get; set; }
        public string? UserEmail { get; set; }
        public string? ApplicationId { get; set; }
        public string? ApplicationName { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
    }

    public class TokenStatsViewModel
    {
        public int TotalTokens { get; set; }
        public int ActiveTokens { get; set; }
        public int ExpiredTokens { get; set; }
        public int RevokedTokens { get; set; }
    }
}
