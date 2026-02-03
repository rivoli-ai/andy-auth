using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Andy.Auth.Configuration;

/// <summary>
/// Configuration options for Andy Auth
/// </summary>
public class AndyAuthOptions
{
    /// <summary>
    /// Authentication provider to use
    /// </summary>
    public AuthProvider Provider { get; set; } = AuthProvider.AndyAuth;

    /// <summary>
    /// Authentication scheme name (default: "Bearer")
    /// </summary>
    public string AuthenticationScheme { get; set; } = JwtBearerDefaults.AuthenticationScheme;

    /// <summary>
    /// OAuth Authority URL (for AndyAuth or custom OIDC providers)
    /// Example: "https://auth.rivoli.ai"
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>
    /// OAuth Audience (API identifier)
    /// Example: "andy-docs-api"
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Additional valid audiences for token validation.
    /// Useful when the API accepts tokens with different audience values
    /// (e.g., MCP resource URLs vs API identifiers).
    /// </summary>
    public string[]? ValidAudiences { get; set; }

    /// <summary>
    /// Azure AD configuration (required when Provider = AzureAD)
    /// </summary>
    public AzureAdOptions? AzureAd { get; set; }

    /// <summary>
    /// Clerk configuration (required when Provider = Clerk)
    /// </summary>
    public ClerkOptions? Clerk { get; set; }

    /// <summary>
    /// Enable automatic user provisioning (Just-In-Time provisioning)
    /// When enabled, users will be automatically created in your database on first login
    /// </summary>
    public bool EnableAutoUserProvisioning { get; set; } = true;

    /// <summary>
    /// Custom JWT Bearer events for advanced scenarios
    /// </summary>
    public JwtBearerEvents? Events { get; set; }

    /// <summary>
    /// Require HTTPS metadata (default: true for production)
    /// Set to false only in development environments
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;
}

/// <summary>
/// Supported authentication providers
/// </summary>
public enum AuthProvider
{
    /// <summary>
    /// Andy Auth (self-hosted OpenIddict server)
    /// </summary>
    AndyAuth,

    /// <summary>
    /// Microsoft Azure Active Directory
    /// </summary>
    AzureAD,

    /// <summary>
    /// Clerk authentication service
    /// </summary>
    Clerk,

    /// <summary>
    /// Custom OpenID Connect provider
    /// </summary>
    Custom
}
