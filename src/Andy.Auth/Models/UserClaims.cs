namespace Andy.Auth.Models;

/// <summary>
/// Standardized user claims extracted from authentication providers
/// </summary>
public class UserClaims
{
    /// <summary>
    /// Unique user identifier from the authentication provider
    /// </summary>
    public required string UserId { get; init; }

    /// <summary>
    /// User's email address
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// User's full name
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// User's given/first name
    /// </summary>
    public string? GivenName { get; init; }

    /// <summary>
    /// User's family/last name
    /// </summary>
    public string? FamilyName { get; init; }

    /// <summary>
    /// URL to user's profile picture
    /// </summary>
    public string? Picture { get; init; }

    /// <summary>
    /// Additional provider-specific claims
    /// </summary>
    public Dictionary<string, string>? AdditionalClaims { get; init; }
}
