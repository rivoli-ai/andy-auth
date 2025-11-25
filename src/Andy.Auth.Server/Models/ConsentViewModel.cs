using System.ComponentModel.DataAnnotations;

namespace Andy.Auth.Server.Models;

/// <summary>
/// View model for the consent screen.
/// </summary>
public class ConsentViewModel
{
    /// <summary>
    /// The client application ID.
    /// </summary>
    public string ClientId { get; set; } = null!;

    /// <summary>
    /// The display name of the client application.
    /// </summary>
    public string ClientName { get; set; } = null!;

    /// <summary>
    /// The URL of the client's logo (optional).
    /// </summary>
    public string? ClientLogoUrl { get; set; }

    /// <summary>
    /// Description of the client application (optional).
    /// </summary>
    public string? ClientDescription { get; set; }

    /// <summary>
    /// The scopes being requested with their descriptions.
    /// </summary>
    public List<ScopeViewModel> RequestedScopes { get; set; } = new();

    /// <summary>
    /// The return URL to redirect after consent decision.
    /// </summary>
    public string ReturnUrl { get; set; } = null!;

    /// <summary>
    /// Whether to remember the consent decision.
    /// </summary>
    public bool RememberConsent { get; set; } = true;
}

/// <summary>
/// View model for a single scope.
/// </summary>
public class ScopeViewModel
{
    /// <summary>
    /// The scope value (e.g., "openid", "profile", "email").
    /// </summary>
    public string Value { get; set; } = null!;

    /// <summary>
    /// The display name of the scope.
    /// </summary>
    public string DisplayName { get; set; } = null!;

    /// <summary>
    /// Description of what the scope allows access to.
    /// </summary>
    public string Description { get; set; } = null!;

    /// <summary>
    /// Whether this scope is required (cannot be deselected).
    /// </summary>
    public bool Required { get; set; }

    /// <summary>
    /// Whether this scope is checked by default.
    /// </summary>
    public bool Checked { get; set; } = true;

    /// <summary>
    /// Icon name for the scope (optional).
    /// </summary>
    public string? Icon { get; set; }
}

/// <summary>
/// Input model for consent form submission.
/// </summary>
public class ConsentInputModel
{
    /// <summary>
    /// The return URL to redirect after consent.
    /// </summary>
    [Required]
    public string ReturnUrl { get; set; } = null!;

    /// <summary>
    /// The scopes the user consented to.
    /// </summary>
    public List<string> ScopesConsented { get; set; } = new();

    /// <summary>
    /// Whether to remember the consent decision.
    /// </summary>
    public bool RememberConsent { get; set; } = true;

    /// <summary>
    /// The user's decision: "allow" or "deny".
    /// </summary>
    [Required]
    public string Decision { get; set; } = null!;
}
