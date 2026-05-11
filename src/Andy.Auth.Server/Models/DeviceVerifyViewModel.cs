namespace Andy.Auth.Server.Models;

/// <summary>
/// Model for the user_code entry form (GET /connect/verify with no
/// pre-filled code, or the form re-rendered after a bad submission).
/// </summary>
public class DeviceVerifyViewModel
{
    public string? UserCode { get; set; }

    /// <summary>Inline error shown above the form (invalid/expired code).</summary>
    public string? Error { get; set; }
}

/// <summary>
/// Model for the consent screen the user sees after entering a valid
/// user_code. Lists the requesting client and the scopes it asked for;
/// the form posts back to /connect/verify with allow/deny.
/// </summary>
public class DeviceVerifyConsentViewModel
{
    public string UserCode { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();
}
