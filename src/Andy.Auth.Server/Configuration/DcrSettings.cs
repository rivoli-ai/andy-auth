namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Configuration settings for Dynamic Client Registration (RFC 7591).
/// </summary>
public class DcrSettings
{
    /// <summary>
    /// Section name in appsettings.json.
    /// </summary>
    public const string SectionName = "DynamicClientRegistration";

    /// <summary>
    /// Enable or disable Dynamic Client Registration feature.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// If true, clients must provide an initial access token to register.
    /// If false, registration is open to anyone (subject to rate limiting).
    /// </summary>
    public bool RequireInitialAccessToken { get; set; } = true;

    /// <summary>
    /// If true, newly registered clients require admin approval before they can be used.
    /// </summary>
    public bool RequireAdminApproval { get; set; } = false;

    /// <summary>
    /// Grant types that dynamically registered clients are allowed to use.
    /// </summary>
    public List<string> AllowedGrantTypes { get; set; } = new()
    {
        "authorization_code",
        "refresh_token",
        "client_credentials"
    };

    /// <summary>
    /// Scopes that dynamically registered clients are allowed to request.
    /// </summary>
    public List<string> AllowedScopes { get; set; } = new()
    {
        "openid",
        "profile",
        "email",
        "offline_access"
    };

    /// <summary>
    /// Default access token lifetime for dynamically registered clients.
    /// </summary>
    public TimeSpan DefaultAccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Default refresh token lifetime for dynamically registered clients.
    /// </summary>
    public TimeSpan DefaultRefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Registration access token lifetime. Set to null for non-expiring tokens.
    /// </summary>
    public TimeSpan? RegistrationAccessTokenLifetime { get; set; } = null;

    /// <summary>
    /// If true, localhost redirect URIs are allowed (useful for development clients).
    /// Should be false in production.
    /// </summary>
    public bool AllowLocalhostRedirectUris { get; set; } = false;

    /// <summary>
    /// If true, HTTP redirect URIs are allowed for localhost (development only).
    /// </summary>
    public bool AllowHttpLocalhostRedirectUris { get; set; } = false;

    /// <summary>
    /// Allowed redirect URI patterns (regex). Empty means all valid URIs are allowed.
    /// </summary>
    public List<string> AllowedRedirectUriPatterns { get; set; } = new();

    /// <summary>
    /// Blocked redirect URI patterns (regex). Takes precedence over allowed patterns.
    /// </summary>
    public List<string> BlockedRedirectUriPatterns { get; set; } = new();

    /// <summary>
    /// Maximum number of redirect URIs per client.
    /// </summary>
    public int MaxRedirectUrisPerClient { get; set; } = 10;

    /// <summary>
    /// Maximum length of client_name.
    /// </summary>
    public int MaxClientNameLength { get; set; } = 200;

    /// <summary>
    /// If true, client secrets never expire. Otherwise, they expire after ClientSecretLifetime.
    /// </summary>
    public bool ClientSecretsNeverExpire { get; set; } = true;

    /// <summary>
    /// Client secret lifetime (only used if ClientSecretsNeverExpire is false).
    /// </summary>
    public TimeSpan ClientSecretLifetime { get; set; } = TimeSpan.FromDays(365);
}
