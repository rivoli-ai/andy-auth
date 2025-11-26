using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Models.Dcr;

/// <summary>
/// Client registration error response per RFC 7591 Section 3.2.2.
/// </summary>
public class ClientRegistrationError
{
    /// <summary>
    /// Error code.
    /// </summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable error description.
    /// </summary>
    [JsonPropertyName("error_description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// Invalid redirect URI (when error is "invalid_redirect_uri").
    /// </summary>
    [JsonPropertyName("invalid_redirect_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? InvalidRedirectUri { get; set; }
}

/// <summary>
/// RFC 7591 error codes.
/// </summary>
public static class DcrErrorCodes
{
    /// <summary>
    /// The value of one or more redirect_uris is invalid.
    /// </summary>
    public const string InvalidRedirectUri = "invalid_redirect_uri";

    /// <summary>
    /// The value of one of the client metadata fields is invalid.
    /// </summary>
    public const string InvalidClientMetadata = "invalid_client_metadata";

    /// <summary>
    /// The software statement presented is invalid.
    /// </summary>
    public const string InvalidSoftwareStatement = "invalid_software_statement";

    /// <summary>
    /// The software statement presented is not approved for use.
    /// </summary>
    public const string UnapprovedSoftwareStatement = "unapproved_software_statement";

    /// <summary>
    /// The authorization server denied the request (generic).
    /// </summary>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// Invalid initial access token.
    /// </summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>
    /// Dynamic client registration is disabled.
    /// </summary>
    public const string RegistrationDisabled = "registration_disabled";
}
