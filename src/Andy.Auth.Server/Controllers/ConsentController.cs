using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Controllers;

/// <summary>
/// Controller for handling OAuth consent screens.
/// </summary>
[Authorize(AuthenticationSchemes = "Identity.Application")]
public class ConsentController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<ConsentController> _logger;

    // Friendly descriptions for standard scopes
    private static readonly Dictionary<string, (string DisplayName, string Description, string Icon)> ScopeDescriptions = new()
    {
        ["openid"] = ("OpenID", "Allow the application to identify you", "id"),
        ["profile"] = ("Profile", "View your profile information (name, picture)", "user"),
        ["email"] = ("Email", "View your email address", "email"),
        ["roles"] = ("Roles", "View your assigned roles", "roles"),
        ["offline_access"] = ("Offline Access", "Access your data when you're not using the app", "refresh"),
    };

    public ConsentController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        ILogger<ConsentController> logger)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _dbContext = dbContext;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Displays the consent screen.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Index(string returnUrl)
    {
        _logger.LogInformation("Consent page requested with returnUrl: {ReturnUrl}", returnUrl);

        if (string.IsNullOrEmpty(returnUrl))
        {
            _logger.LogWarning("Consent page accessed without returnUrl");
            return BadRequest("Return URL is required.");
        }

        try
        {
            var viewModel = await BuildConsentViewModelAsync(returnUrl);
            if (viewModel == null)
            {
                _logger.LogWarning("BuildConsentViewModelAsync returned null for returnUrl: {ReturnUrl}", returnUrl);
                return BadRequest("Invalid authorization request.");
            }

            _logger.LogInformation("Consent page rendering for client: {ClientId}", viewModel.ClientId);
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error building consent view model for returnUrl: {ReturnUrl}", returnUrl);
            return BadRequest($"Error processing consent request: {ex.Message}");
        }
    }

    /// <summary>
    /// Processes the user's consent decision.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(ConsentInputModel model)
    {
        if (!ModelState.IsValid)
        {
            var viewModel = await BuildConsentViewModelAsync(model.ReturnUrl);
            if (viewModel == null)
            {
                return BadRequest("Invalid authorization request.");
            }
            return View(viewModel);
        }

        // Parse the return URL to get the authorization parameters
        var uri = new Uri(model.ReturnUrl, UriKind.RelativeOrAbsolute);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

        if (!query.TryGetValue("client_id", out var clientIdValues) || string.IsNullOrEmpty(clientIdValues.FirstOrDefault()))
        {
            return BadRequest("Client ID not found in return URL.");
        }

        var clientId = clientIdValues.First()!;
        var userId = _userManager.GetUserId(User)!;

        if (model.Decision == "deny")
        {
            _logger.LogInformation("User {UserId} denied consent for client {ClientId}", userId, clientId);

            // Redirect back with error
            var errorUrl = AppendQueryString(model.ReturnUrl, "error", "access_denied");
            errorUrl = AppendQueryString(errorUrl, "error_description", "The user denied the consent request.");
            return Redirect(errorUrl);
        }

        // User allowed - save consent
        var scopesConsented = model.ScopesConsented ?? new List<string>();

        // Always include openid scope if it was requested
        if (query.TryGetValue("scope", out var scopeValues))
        {
            var requestedScopes = scopeValues.First()?.Split(' ') ?? Array.Empty<string>();
            if (requestedScopes.Contains("openid") && !scopesConsented.Contains("openid"))
            {
                scopesConsented.Add("openid");
            }
        }

        // Save or update consent
        var existingConsent = await _dbContext.UserConsents
            .FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId);

        if (existingConsent != null)
        {
            existingConsent.SetScopes(scopesConsented);
            existingConsent.GrantedAt = DateTime.UtcNow;
            existingConsent.RememberConsent = model.RememberConsent;
            existingConsent.ExpiresAt = model.RememberConsent ? DateTime.UtcNow.AddDays(90) : null;
        }
        else
        {
            var newConsent = new UserConsent
            {
                UserId = userId,
                ClientId = clientId,
                RememberConsent = model.RememberConsent,
                ExpiresAt = model.RememberConsent ? DateTime.UtcNow.AddDays(90) : null
            };
            newConsent.SetScopes(scopesConsented);
            _dbContext.UserConsents.Add(newConsent);
        }

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("User {UserId} granted consent for client {ClientId} with scopes: {Scopes}",
            userId, clientId, string.Join(", ", scopesConsented));

        // Add consent granted marker to return URL
        var consentUrl = AppendQueryString(model.ReturnUrl, "consent_granted", "true");
        return Redirect(consentUrl);
    }

    /// <summary>
    /// Shows the user's active consents for management.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> MyConsents()
    {
        var userId = _userManager.GetUserId(User)!;
        var consents = await _dbContext.UserConsents
            .Where(c => c.UserId == userId)
            .OrderByDescending(c => c.GrantedAt)
            .ToListAsync();

        var consentViewModels = new List<UserConsentViewModel>();

        foreach (var consent in consents)
        {
            var application = await _applicationManager.FindByClientIdAsync(consent.ClientId);
            var displayName = application != null
                ? await _applicationManager.GetDisplayNameAsync(application) ?? consent.ClientId
                : consent.ClientId;

            consentViewModels.Add(new UserConsentViewModel
            {
                Id = consent.Id,
                ClientId = consent.ClientId,
                ClientName = displayName,
                Scopes = consent.ScopesList.ToList(),
                GrantedAt = consent.GrantedAt,
                ExpiresAt = consent.ExpiresAt,
                IsValid = consent.IsValid
            });
        }

        return View(consentViewModels);
    }

    /// <summary>
    /// Revokes a user's consent for a specific client.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(int id)
    {
        var userId = _userManager.GetUserId(User)!;
        var consent = await _dbContext.UserConsents
            .FirstOrDefaultAsync(c => c.Id == id && c.UserId == userId);

        if (consent == null)
        {
            return NotFound();
        }

        _dbContext.UserConsents.Remove(consent);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("User {UserId} revoked consent for client {ClientId}", userId, consent.ClientId);

        TempData["Message"] = $"Access for {consent.ClientId} has been revoked.";
        return RedirectToAction(nameof(MyConsents));
    }

    private async Task<ConsentViewModel?> BuildConsentViewModelAsync(string returnUrl)
    {
        // Parse the return URL to get authorization parameters
        var uri = new Uri(returnUrl, UriKind.RelativeOrAbsolute);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

        if (!query.TryGetValue("client_id", out var clientIdValues) || string.IsNullOrEmpty(clientIdValues.FirstOrDefault()))
        {
            return null;
        }

        var clientId = clientIdValues.First()!;
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return null;
        }

        var clientName = await _applicationManager.GetDisplayNameAsync(application) ?? clientId;

        // Get requested scopes
        var requestedScopes = new List<string>();
        if (query.TryGetValue("scope", out var scopeValues) && !string.IsNullOrEmpty(scopeValues.FirstOrDefault()))
        {
            requestedScopes = scopeValues.First()!.Split(' ').ToList();
        }

        // Build scope view models
        var scopeViewModels = new List<ScopeViewModel>();
        foreach (var scope in requestedScopes)
        {
            var scopeVm = new ScopeViewModel
            {
                Value = scope,
                Checked = true
            };

            if (ScopeDescriptions.TryGetValue(scope, out var description))
            {
                scopeVm.DisplayName = description.DisplayName;
                scopeVm.Description = description.Description;
                scopeVm.Icon = description.Icon;
                scopeVm.Required = scope == "openid"; // OpenID scope is always required
            }
            else
            {
                // Try to get description from scope manager for custom scopes
                var scopeEntity = await _scopeManager.FindByNameAsync(scope);
                if (scopeEntity != null)
                {
                    scopeVm.DisplayName = await _scopeManager.GetDisplayNameAsync(scopeEntity) ?? scope;
                    scopeVm.Description = await _scopeManager.GetDescriptionAsync(scopeEntity) ?? $"Access to {scope}";
                }
                else
                {
                    scopeVm.DisplayName = scope;
                    scopeVm.Description = $"Access to {scope}";
                }
                scopeVm.Icon = "api";
            }

            scopeViewModels.Add(scopeVm);
        }

        return new ConsentViewModel
        {
            ClientId = clientId,
            ClientName = clientName,
            RequestedScopes = scopeViewModels,
            ReturnUrl = returnUrl,
            RememberConsent = true
        };
    }

    private static string AppendQueryString(string url, string key, string value)
    {
        var separator = url.Contains('?') ? "&" : "?";
        return $"{url}{separator}{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}";
    }
}

/// <summary>
/// View model for displaying user's granted consents.
/// </summary>
public class UserConsentViewModel
{
    public int Id { get; set; }
    public string ClientId { get; set; } = null!;
    public string ClientName { get; set; } = null!;
    public List<string> Scopes { get; set; } = new();
    public DateTime GrantedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool IsValid { get; set; }
}
