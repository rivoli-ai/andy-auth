namespace Andy.Auth.Configuration;

/// <summary>
/// Azure Active Directory configuration options
/// </summary>
public class AzureAdOptions
{
    /// <summary>
    /// Azure AD Tenant ID (Directory ID)
    /// Example: "12345678-1234-1234-1234-123456789012"
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// Application (client) ID from Azure AD app registration
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Azure AD instance URL
    /// Default: "https://login.microsoftonline.com/"
    /// </summary>
    public string Instance { get; set; } = "https://login.microsoftonline.com/";

    /// <summary>
    /// Azure AD domain (optional)
    /// Example: "contoso.onmicrosoft.com"
    /// </summary>
    public string? Domain { get; set; }
}
