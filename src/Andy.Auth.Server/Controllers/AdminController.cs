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
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        ILogger<AdminController> logger)
    {
        _context = context;
        _userManager = userManager;
        _applicationManager = applicationManager;
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

    public async Task<IActionResult> Users(int page = 1, int pageSize = 20)
    {
        var totalUsers = await _userManager.Users.CountAsync();
        var users = await _userManager.Users
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalUsers / (double)pageSize);
        ViewBag.TotalUsers = totalUsers;

        return View(users);
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

        // Soft delete
        user.DeletedAt = DateTime.UtcNow;
        user.IsActive = false;

        await _userManager.UpdateAsync(user);
        await LogAuditAsync("UserDeleted", user.Id, user.Email);

        TempData["SuccessMessage"] = $"User {user.Email} has been deleted.";
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

    public async Task<IActionResult> AuditLogs(int page = 1, int pageSize = 50)
    {
        var totalLogs = await _context.AuditLogs.CountAsync();
        var logs = await _context.AuditLogs
            .OrderByDescending(l => l.PerformedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(totalLogs / (double)pageSize);
        ViewBag.TotalLogs = totalLogs;

        return View(logs);
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
}
