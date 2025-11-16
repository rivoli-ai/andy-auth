namespace Andy.Auth.Configuration;

/// <summary>
/// Clerk authentication service configuration options
/// </summary>
public class ClerkOptions
{
    /// <summary>
    /// Clerk domain (e.g., "trusted-camel-19.clerk.accounts.dev")
    /// </summary>
    public string? Domain { get; set; }

    /// <summary>
    /// OAuth audience (optional)
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// OAuth client ID for Clerk public client
    /// </summary>
    public string? ClientId { get; set; }
}
