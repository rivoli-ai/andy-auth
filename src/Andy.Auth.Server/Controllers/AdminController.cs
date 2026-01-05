using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Controllers;

[Authorize(Roles = "Admin", AuthenticationSchemes = "Identity.Application")]
public class AdminController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictTokenManager tokenManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IAuditService auditService,
        ILogger<AdminController> logger)
    {
        _context = context;
        _userManager = userManager;
        _applicationManager = applicationManager;
        _tokenManager = tokenManager;
        _authorizationManager = authorizationManager;
        _auditService = auditService;
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

        // Get all DCR metadata for lookup
        var dcrMetadata = await _context.DynamicClientRegistrations.ToDictionaryAsync(d => d.ClientId);

        // Get all OpenIddict applications
        await foreach (var application in _applicationManager.ListAsync())
        {
            var clientId = await _applicationManager.GetClientIdAsync(application);
            var displayName = await _applicationManager.GetDisplayNameAsync(application);
            var redirectUris = await _applicationManager.GetRedirectUrisAsync(application);
            var clientType = await _applicationManager.GetClientTypeAsync(application);
            var permissions = await _applicationManager.GetPermissionsAsync(application);

            var clientViewModel = new ClientViewModel
            {
                ClientId = clientId ?? "Unknown",
                DisplayName = displayName ?? "Unknown",
                RedirectUris = redirectUris.Select(uri => uri.ToString()).ToList(),
                ClientType = clientType ?? "public",
                Permissions = permissions.ToList()
            };

            // Check if this client was dynamically registered
            if (clientId != null && dcrMetadata.TryGetValue(clientId, out var dcr))
            {
                clientViewModel.IsDynamicallyRegistered = true;
                clientViewModel.RegisteredAt = dcr.RegisteredAt;
                clientViewModel.IsApproved = dcr.IsApproved;
                clientViewModel.IsDisabled = dcr.IsDisabled;
            }

            clients.Add(clientViewModel);
        }

        return View(clients);
    }

    [HttpGet]
    public IActionResult CreateClient()
    {
        return View(new CreateClientViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateClient(CreateClientViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Check if client ID already exists
        var existingClient = await _applicationManager.FindByClientIdAsync(model.ClientId);
        if (existingClient != null)
        {
            ModelState.AddModelError("ClientId", "A client with this ID already exists.");
            return View(model);
        }

        // Build the application descriptor
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = model.ClientId,
            DisplayName = model.DisplayName,
            ConsentType = model.RequireConsent ? OpenIddictConstants.ConsentTypes.Explicit : OpenIddictConstants.ConsentTypes.Implicit
        };

        // Set client type and secret
        if (model.ClientType == "confidential")
        {
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
            descriptor.ClientSecret = model.ClientSecret;
        }
        else
        {
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Public;
        }

        // Add redirect URIs
        if (!string.IsNullOrWhiteSpace(model.RedirectUris))
        {
            foreach (var uri in model.RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.RedirectUris.Add(parsedUri);
                }
            }
        }

        // Add post-logout redirect URIs
        if (!string.IsNullOrWhiteSpace(model.PostLogoutRedirectUris))
        {
            foreach (var uri in model.PostLogoutRedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.PostLogoutRedirectUris.Add(parsedUri);
                }
            }
        }

        // Add permissions
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        if (model.AllowAuthorizationCodeFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        if (model.AllowClientCredentialsFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        }

        if (model.AllowRefreshTokens)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        }

        // Add scope permissions
        if (model.AllowOpenIdScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
        if (model.AllowProfileScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
        if (model.AllowEmailScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
        if (model.AllowRolesScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Roles);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access");

        // Create the client
        await _applicationManager.CreateAsync(descriptor);

        await LogAuditAsync("ClientCreated", null, null, $"Client ID: {model.ClientId}, Display Name: {model.DisplayName}");

        TempData["SuccessMessage"] = $"Client '{model.DisplayName}' created successfully.";
        TempData["NewClientSecret"] = model.ClientType == "confidential" ? model.ClientSecret : null;
        TempData["NewClientId"] = model.ClientId;

        return RedirectToAction(nameof(Clients));
    }

    [HttpGet]
    public async Task<IActionResult> EditClient(string id)
    {
        var application = await _applicationManager.FindByClientIdAsync(id);
        if (application == null)
        {
            return NotFound();
        }

        var clientId = await _applicationManager.GetClientIdAsync(application);
        var displayName = await _applicationManager.GetDisplayNameAsync(application);
        var clientType = await _applicationManager.GetClientTypeAsync(application);
        var redirectUris = await _applicationManager.GetRedirectUrisAsync(application);
        var postLogoutRedirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(application);
        var permissions = await _applicationManager.GetPermissionsAsync(application);
        var consentType = await _applicationManager.GetConsentTypeAsync(application);

        var model = new EditClientViewModel
        {
            OriginalClientId = clientId!,
            ClientId = clientId!,
            DisplayName = displayName ?? "",
            ClientType = clientType ?? "public",
            RedirectUris = string.Join("\n", redirectUris),
            PostLogoutRedirectUris = string.Join("\n", postLogoutRedirectUris),
            RequireConsent = consentType == OpenIddictConstants.ConsentTypes.Explicit,
            AllowAuthorizationCodeFlow = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode),
            AllowClientCredentialsFlow = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials),
            AllowRefreshTokens = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken),
            AllowOpenIdScope = permissions.Contains(OpenIddictConstants.Permissions.Scopes.Email) || permissions.Any(p => p.Contains("openid")),
            AllowProfileScope = permissions.Contains(OpenIddictConstants.Permissions.Scopes.Profile),
            AllowEmailScope = permissions.Contains(OpenIddictConstants.Permissions.Scopes.Email),
            AllowRolesScope = permissions.Contains(OpenIddictConstants.Permissions.Scopes.Roles)
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditClient(EditClientViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var application = await _applicationManager.FindByClientIdAsync(model.OriginalClientId);
        if (application == null)
        {
            return NotFound();
        }

        // Build the updated descriptor
        var descriptor = new OpenIddictApplicationDescriptor();
        await _applicationManager.PopulateAsync(descriptor, application);

        descriptor.DisplayName = model.DisplayName;
        descriptor.ConsentType = model.RequireConsent ? OpenIddictConstants.ConsentTypes.Explicit : OpenIddictConstants.ConsentTypes.Implicit;

        // Update redirect URIs
        descriptor.RedirectUris.Clear();
        if (!string.IsNullOrWhiteSpace(model.RedirectUris))
        {
            foreach (var uri in model.RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.RedirectUris.Add(parsedUri);
                }
            }
        }

        // Update post-logout redirect URIs
        descriptor.PostLogoutRedirectUris.Clear();
        if (!string.IsNullOrWhiteSpace(model.PostLogoutRedirectUris))
        {
            foreach (var uri in model.PostLogoutRedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.PostLogoutRedirectUris.Add(parsedUri);
                }
            }
        }

        // Update permissions
        descriptor.Permissions.Clear();
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        if (model.AllowAuthorizationCodeFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        if (model.AllowClientCredentialsFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        }

        if (model.AllowRefreshTokens)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        }

        if (model.AllowOpenIdScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
        if (model.AllowProfileScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
        if (model.AllowEmailScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
        if (model.AllowRolesScope) descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Roles);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access");

        // Update the client
        await _applicationManager.UpdateAsync(application, descriptor);

        await LogAuditAsync("ClientUpdated", null, null, $"Client ID: {model.ClientId}, Display Name: {model.DisplayName}");

        TempData["SuccessMessage"] = $"Client '{model.DisplayName}' updated successfully.";
        return RedirectToAction(nameof(Clients));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteClient(string clientId)
    {
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            TempData["ErrorMessage"] = "Client not found.";
            return RedirectToAction(nameof(Clients));
        }

        var displayName = await _applicationManager.GetDisplayNameAsync(application);

        // Delete the client
        await _applicationManager.DeleteAsync(application);

        await LogAuditAsync("ClientDeleted", null, null, $"Client ID: {clientId}, Display Name: {displayName}");

        TempData["SuccessMessage"] = $"Client '{displayName}' deleted successfully.";
        return RedirectToAction(nameof(Clients));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegenerateClientSecret(string clientId)
    {
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            TempData["ErrorMessage"] = "Client not found.";
            return RedirectToAction(nameof(Clients));
        }

        var clientType = await _applicationManager.GetClientTypeAsync(application);
        if (clientType != OpenIddictConstants.ClientTypes.Confidential)
        {
            TempData["ErrorMessage"] = "Cannot regenerate secret for public clients.";
            return RedirectToAction(nameof(Clients));
        }

        // Generate new secret
        var newSecret = GenerateClientSecret();

        // Update the client with new secret
        var descriptor = new OpenIddictApplicationDescriptor();
        await _applicationManager.PopulateAsync(descriptor, application);
        descriptor.ClientSecret = newSecret;
        await _applicationManager.UpdateAsync(application, descriptor);

        var displayName = await _applicationManager.GetDisplayNameAsync(application);
        await LogAuditAsync("ClientSecretRegenerated", null, null, $"Client ID: {clientId}, Display Name: {displayName}");

        TempData["SuccessMessage"] = $"Client secret regenerated for '{displayName}'.";
        TempData["NewClientSecret"] = newSecret;
        TempData["NewClientId"] = clientId;

        return RedirectToAction(nameof(Clients));
    }

    private static string GenerateClientSecret()
    {
        var bytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
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
        // Use EF Core directly for efficient database queries instead of loading all tokens into memory
        var tokenDbSet = _context.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken>();
        var appDbSet = _context.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>();

        // Build base query
        var query = tokenDbSet.AsQueryable();

        // Apply status filter at database level
        if (!string.IsNullOrWhiteSpace(status))
        {
            query = query.Where(t => t.Status == status.ToLower());
        }

        // Get total counts for statistics (efficient COUNT queries)
        var totalTokens = await tokenDbSet.CountAsync();
        var activeTokens = await tokenDbSet.CountAsync(t => t.Status == "valid");
        var expiredTokens = await tokenDbSet.CountAsync(t => t.ExpirationDate != null && t.ExpirationDate < DateTime.UtcNow);
        var revokedTokens = await tokenDbSet.CountAsync(t => t.Status == "revoked" || t.Status == "redeemed");

        var stats = new TokenStatsViewModel
        {
            TotalTokens = totalTokens,
            ActiveTokens = activeTokens,
            ExpiredTokens = expiredTokens,
            RevokedTokens = revokedTokens
        };

        // Apply search filter if provided (requires joining with users/apps)
        IQueryable<TokenViewModel> tokenQuery;

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.ToLower();
            tokenQuery = from t in query
                         join app in appDbSet on t.Application!.Id equals app.Id into apps
                         from app in apps.DefaultIfEmpty()
                         join user in _userManager.Users on t.Subject equals user.Id into users
                         from user in users.DefaultIfEmpty()
                         where (user != null && user.Email != null && user.Email.ToLower().Contains(searchLower)) ||
                               (app != null && app.DisplayName != null && app.DisplayName.ToLower().Contains(searchLower)) ||
                               (t.Subject != null && t.Subject.ToLower().Contains(searchLower))
                         orderby t.CreationDate descending
                         select new TokenViewModel
                         {
                             Id = t.Id,
                             Subject = t.Subject,
                             UserEmail = user != null ? user.Email : null,
                             ApplicationId = app != null ? app.Id : null,
                             ApplicationName = app != null ? app.DisplayName : null,
                             CreatedAt = t.CreationDate,
                             ExpiresAt = t.ExpirationDate,
                             Status = t.Status ?? "Unknown",
                             Type = t.Type ?? "Unknown"
                         };
        }
        else
        {
            tokenQuery = from t in query
                         join app in appDbSet on t.Application!.Id equals app.Id into apps
                         from app in apps.DefaultIfEmpty()
                         join user in _userManager.Users on t.Subject equals user.Id into users
                         from user in users.DefaultIfEmpty()
                         orderby t.CreationDate descending
                         select new TokenViewModel
                         {
                             Id = t.Id,
                             Subject = t.Subject,
                             UserEmail = user != null ? user.Email : null,
                             ApplicationId = app != null ? app.Id : null,
                             ApplicationName = app != null ? app.DisplayName : null,
                             CreatedAt = t.CreationDate,
                             ExpiresAt = t.ExpirationDate,
                             Status = t.Status ?? "Unknown",
                             Type = t.Type ?? "Unknown"
                         };
        }

        // Get filtered count for pagination
        var filteredCount = await tokenQuery.CountAsync();

        // Apply pagination at database level
        var tokens = await tokenQuery
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        ViewBag.CurrentPage = page;
        ViewBag.TotalPages = (int)Math.Ceiling(filteredCount / (double)pageSize);
        ViewBag.TotalTokens = filteredCount;
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

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ApproveDcrClient(string clientId)
    {
        var dcr = await _context.DynamicClientRegistrations
            .FirstOrDefaultAsync(d => d.ClientId == clientId);

        if (dcr == null)
        {
            TempData["ErrorMessage"] = "Client not found or was not dynamically registered.";
            return RedirectToAction(nameof(Clients));
        }

        var currentUser = await _userManager.GetUserAsync(User);
        dcr.IsApproved = true;
        dcr.ApprovedById = currentUser?.Id;
        dcr.ApprovedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogAuditAsync("DcrClientApproved", null, null, $"Client ID: {clientId}");

        TempData["SuccessMessage"] = $"DCR client '{clientId}' has been approved.";
        return RedirectToAction(nameof(Clients));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DisableDcrClient(string clientId, string? reason)
    {
        var dcr = await _context.DynamicClientRegistrations
            .FirstOrDefaultAsync(d => d.ClientId == clientId);

        if (dcr == null)
        {
            TempData["ErrorMessage"] = "Client not found or was not dynamically registered.";
            return RedirectToAction(nameof(Clients));
        }

        var currentUser = await _userManager.GetUserAsync(User);
        dcr.IsDisabled = true;
        dcr.DisabledAt = DateTime.UtcNow;
        dcr.DisabledBy = currentUser?.Id;
        dcr.DisabledReason = reason;

        await _context.SaveChangesAsync();

        await LogAuditAsync("DcrClientDisabled", null, null, $"Client ID: {clientId}, Reason: {reason ?? "No reason provided"}");

        TempData["SuccessMessage"] = $"DCR client '{clientId}' has been disabled.";
        return RedirectToAction(nameof(Clients));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableDcrClient(string clientId)
    {
        var dcr = await _context.DynamicClientRegistrations
            .FirstOrDefaultAsync(d => d.ClientId == clientId);

        if (dcr == null)
        {
            TempData["ErrorMessage"] = "Client not found or was not dynamically registered.";
            return RedirectToAction(nameof(Clients));
        }

        dcr.IsDisabled = false;
        dcr.DisabledAt = null;
        dcr.DisabledBy = null;
        dcr.DisabledReason = null;

        await _context.SaveChangesAsync();

        await LogAuditAsync("DcrClientEnabled", null, null, $"Client ID: {clientId}");

        TempData["SuccessMessage"] = $"DCR client '{clientId}' has been enabled.";
        return RedirectToAction(nameof(Clients));
    }

    private async Task LogAuditAsync(string action, string? targetUserId = null, string? targetUserEmail = null, string? details = null)
    {
        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null)
            return;

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _auditService.LogAsync(
            action,
            currentUser.Id,
            currentUser.Email ?? "Unknown",
            targetUserId,
            targetUserEmail,
            details,
            ipAddress);
    }

    public class ClientViewModel
    {
        public string ClientId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public List<string> RedirectUris { get; set; } = new();
        public string ClientType { get; set; } = "public";
        public List<string> Permissions { get; set; } = new();
        public bool IsDynamicallyRegistered { get; set; } = false;
        public DateTime? RegisteredAt { get; set; }
        public bool IsApproved { get; set; } = true;
        public bool IsDisabled { get; set; } = false;
    }

    public class CreateClientViewModel
    {
        [System.ComponentModel.DataAnnotations.Required]
        [System.ComponentModel.DataAnnotations.StringLength(100, MinimumLength = 3)]
        [System.ComponentModel.DataAnnotations.RegularExpression(@"^[a-z0-9\-_]+$", ErrorMessage = "Client ID can only contain lowercase letters, numbers, hyphens, and underscores.")]
        public string ClientId { get; set; } = string.Empty;

        [System.ComponentModel.DataAnnotations.Required]
        [System.ComponentModel.DataAnnotations.StringLength(200)]
        public string DisplayName { get; set; } = string.Empty;

        [System.ComponentModel.DataAnnotations.Required]
        public string ClientType { get; set; } = "public";

        public string? ClientSecret { get; set; }

        public string? RedirectUris { get; set; }

        public string? PostLogoutRedirectUris { get; set; }

        public bool RequireConsent { get; set; } = true;

        public bool AllowAuthorizationCodeFlow { get; set; } = true;

        public bool AllowClientCredentialsFlow { get; set; } = false;

        public bool AllowRefreshTokens { get; set; } = true;

        public bool AllowOpenIdScope { get; set; } = true;

        public bool AllowProfileScope { get; set; } = true;

        public bool AllowEmailScope { get; set; } = true;

        public bool AllowRolesScope { get; set; } = false;
    }

    public class EditClientViewModel
    {
        public string OriginalClientId { get; set; } = string.Empty;

        [System.ComponentModel.DataAnnotations.Required]
        public string ClientId { get; set; } = string.Empty;

        [System.ComponentModel.DataAnnotations.Required]
        [System.ComponentModel.DataAnnotations.StringLength(200)]
        public string DisplayName { get; set; } = string.Empty;

        public string ClientType { get; set; } = "public";

        public string? RedirectUris { get; set; }

        public string? PostLogoutRedirectUris { get; set; }

        public bool RequireConsent { get; set; }

        public bool AllowAuthorizationCodeFlow { get; set; }

        public bool AllowClientCredentialsFlow { get; set; }

        public bool AllowRefreshTokens { get; set; }

        public bool AllowOpenIdScope { get; set; }

        public bool AllowProfileScope { get; set; }

        public bool AllowEmailScope { get; set; }

        public bool AllowRolesScope { get; set; }
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
