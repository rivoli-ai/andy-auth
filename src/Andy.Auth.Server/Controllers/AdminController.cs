using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Controllers;

[Authorize]
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

    public class ClientViewModel
    {
        public string ClientId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public List<string> RedirectUris { get; set; } = new();
    }
}
