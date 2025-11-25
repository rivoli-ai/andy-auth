using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Andy.Auth.Server.Controllers;

/// <summary>
/// Controller for managing user sessions.
/// </summary>
[Authorize]
public class SessionController : Controller
{
    private readonly SessionService _sessionService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<SessionController> _logger;

    public SessionController(
        SessionService sessionService,
        UserManager<ApplicationUser> userManager,
        ILogger<SessionController> logger)
    {
        _sessionService = sessionService;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Displays the user's active sessions.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var userId = _userManager.GetUserId(User)!;
        var sessions = await _sessionService.GetActiveSessionsAsync(userId);
        var currentSessionId = GetCurrentSessionId();

        var viewModel = new SessionsViewModel
        {
            Sessions = sessions.Select(s => new SessionViewModel
            {
                Id = s.Id,
                SessionId = s.SessionId,
                DeviceDescription = s.DeviceDescription,
                BrowserDescription = s.BrowserDescription,
                IpAddress = s.IpAddress ?? "Unknown",
                Location = s.Location ?? "Unknown location",
                CreatedAt = s.CreatedAt,
                LastActivity = s.LastActivity,
                IsCurrentSession = s.SessionId == currentSessionId
            }).ToList(),
            MaxConcurrentSessions = _sessionService.MaxConcurrentSessions
        };

        return View(viewModel);
    }

    /// <summary>
    /// Revokes a specific session.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(int id)
    {
        var userId = _userManager.GetUserId(User)!;
        var success = await _sessionService.RevokeSessionAsync(id, userId, "User-initiated revocation");

        if (success)
        {
            TempData["Message"] = "Session has been revoked.";
        }
        else
        {
            TempData["Error"] = "Could not revoke session.";
        }

        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Revokes all sessions except the current one.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeAllOther()
    {
        var userId = _userManager.GetUserId(User)!;
        var currentSessionId = GetCurrentSessionId();

        if (string.IsNullOrEmpty(currentSessionId))
        {
            TempData["Error"] = "Could not identify current session.";
            return RedirectToAction(nameof(Index));
        }

        var count = await _sessionService.RevokeAllOtherSessionsAsync(userId, currentSessionId);
        TempData["Message"] = $"{count} session(s) have been revoked.";

        return RedirectToAction(nameof(Index));
    }

    private string? GetCurrentSessionId()
    {
        var sessionClaim = User.FindFirst("session_id");
        if (sessionClaim != null)
        {
            return sessionClaim.Value;
        }

        // Fallback: use authentication ticket ID hash
        if (Request.Cookies.TryGetValue(".AspNetCore.Identity.Application", out var cookie))
        {
            return Convert.ToBase64String(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(cookie)
                )
            )[..32];
        }

        return null;
    }
}

/// <summary>
/// View model for the sessions list page.
/// </summary>
public class SessionsViewModel
{
    public List<SessionViewModel> Sessions { get; set; } = new();
    public int MaxConcurrentSessions { get; set; }
}

/// <summary>
/// View model for a single session.
/// </summary>
public class SessionViewModel
{
    public int Id { get; set; }
    public string SessionId { get; set; } = null!;
    public string DeviceDescription { get; set; } = null!;
    public string BrowserDescription { get; set; } = null!;
    public string IpAddress { get; set; } = null!;
    public string Location { get; set; } = null!;
    public DateTime CreatedAt { get; set; }
    public DateTime LastActivity { get; set; }
    public bool IsCurrentSession { get; set; }
}
