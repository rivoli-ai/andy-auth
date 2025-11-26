namespace Andy.Auth.Server.Data;

/// <summary>
/// Metadata for dynamically registered OAuth clients.
/// Tracks additional information about clients registered via RFC 7591.
/// </summary>
public class DynamicClientRegistration
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// The client ID (matches OpenIddict application).
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// When the client was dynamically registered.
    /// </summary>
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Unix timestamp of when the client ID was issued.
    /// </summary>
    public long ClientIdIssuedAt { get; set; }

    /// <summary>
    /// Unix timestamp of when the client secret expires (0 = never).
    /// </summary>
    public long ClientSecretExpiresAt { get; set; } = 0;

    /// <summary>
    /// Initial access token that was used to register this client (if any).
    /// </summary>
    public int? InitialAccessTokenId { get; set; }

    /// <summary>
    /// Navigation property to the initial access token.
    /// </summary>
    public InitialAccessToken? InitialAccessToken { get; set; }

    /// <summary>
    /// Whether this client requires admin approval to be used.
    /// </summary>
    public bool RequiresApproval { get; set; } = false;

    /// <summary>
    /// Whether admin has approved this client.
    /// </summary>
    public bool IsApproved { get; set; } = true;

    /// <summary>
    /// Admin who approved this client (if applicable).
    /// </summary>
    public string? ApprovedById { get; set; }

    /// <summary>
    /// When the client was approved.
    /// </summary>
    public DateTime? ApprovedAt { get; set; }

    /// <summary>
    /// Whether this client has been disabled by admin.
    /// </summary>
    public bool IsDisabled { get; set; } = false;

    /// <summary>
    /// When the client was disabled.
    /// </summary>
    public DateTime? DisabledAt { get; set; }

    /// <summary>
    /// Admin who disabled this client.
    /// </summary>
    public string? DisabledBy { get; set; }

    /// <summary>
    /// Reason for disabling.
    /// </summary>
    public string? DisabledReason { get; set; }

    /// <summary>
    /// IP address from which the client was registered.
    /// </summary>
    public string? RegisteredFromIp { get; set; }

    /// <summary>
    /// User agent of the registration request.
    /// </summary>
    public string? RegisteredUserAgent { get; set; }

    /// <summary>
    /// Additional metadata stored as JSON.
    /// </summary>
    public string? MetadataJson { get; set; }

    /// <summary>
    /// Navigation property to the registration access token.
    /// </summary>
    public RegistrationAccessToken? RegistrationAccessToken { get; set; }

    /// <summary>
    /// Whether the client can be used (approved and not disabled).
    /// </summary>
    public bool IsActive => IsApproved && !IsDisabled;
}
