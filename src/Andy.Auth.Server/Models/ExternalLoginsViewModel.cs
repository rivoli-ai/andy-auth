namespace Andy.Auth.Server.Models;

/// <summary>
/// Backs the external-login management page (andy-auth#119).
/// </summary>
public class ExternalLoginsViewModel
{
    /// <summary>External identities currently attached to the account.</summary>
    public List<LinkedExternalLogin> LinkedLogins { get; set; } = new();

    /// <summary>Configured providers not yet attached.</summary>
    public List<AvailableExternalProvider> AvailableProviders { get; set; } = new();

    /// <summary>
    /// Whether the account has a local password. Linking requires
    /// re-authentication with it, and the last external login cannot be removed
    /// without one.
    /// </summary>
    public bool HasPassword { get; set; }
}

public class LinkedExternalLogin
{
    public string LoginProvider { get; set; } = null!;
    public string ProviderDisplayName { get; set; } = null!;
    public string ProviderKey { get; set; } = null!;
}

public class AvailableExternalProvider
{
    public string Name { get; set; } = null!;
    public string DisplayName { get; set; } = null!;
}
