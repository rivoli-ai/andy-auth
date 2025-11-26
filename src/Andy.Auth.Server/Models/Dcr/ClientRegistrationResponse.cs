using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Models.Dcr;

/// <summary>
/// Client registration response per RFC 7591 Section 3.2.1.
/// </summary>
public class ClientRegistrationResponse
{
    /// <summary>
    /// OAuth 2.0 client identifier.
    /// </summary>
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// OAuth 2.0 client secret (for confidential clients).
    /// </summary>
    [JsonPropertyName("client_secret")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Time at which the client identifier was issued (Unix timestamp).
    /// </summary>
    [JsonPropertyName("client_id_issued_at")]
    public long ClientIdIssuedAt { get; set; }

    /// <summary>
    /// Time at which the client secret will expire (Unix timestamp).
    /// 0 means it will not expire.
    /// </summary>
    [JsonPropertyName("client_secret_expires_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? ClientSecretExpiresAt { get; set; }

    /// <summary>
    /// Registration access token for managing this client.
    /// </summary>
    [JsonPropertyName("registration_access_token")]
    public string RegistrationAccessToken { get; set; } = string.Empty;

    /// <summary>
    /// URI of the client configuration endpoint.
    /// </summary>
    [JsonPropertyName("registration_client_uri")]
    public string RegistrationClientUri { get; set; } = string.Empty;

    // Echo back all the client metadata

    /// <summary>
    /// Array of redirect URIs.
    /// </summary>
    [JsonPropertyName("redirect_uris")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? RedirectUris { get; set; }

    /// <summary>
    /// JSON array containing OAuth 2.0 response_type values.
    /// </summary>
    [JsonPropertyName("response_types")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? ResponseTypes { get; set; }

    /// <summary>
    /// JSON array containing OAuth 2.0 grant_type values.
    /// </summary>
    [JsonPropertyName("grant_types")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? GrantTypes { get; set; }

    /// <summary>
    /// Kind of the application.
    /// </summary>
    [JsonPropertyName("application_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApplicationType { get; set; }

    /// <summary>
    /// Array of email addresses of contacts.
    /// </summary>
    [JsonPropertyName("contacts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Contacts { get; set; }

    /// <summary>
    /// Human-readable name of the client.
    /// </summary>
    [JsonPropertyName("client_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientName { get; set; }

    /// <summary>
    /// URL that references a logo for the client.
    /// </summary>
    [JsonPropertyName("logo_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LogoUri { get; set; }

    /// <summary>
    /// URL of the home page of the client.
    /// </summary>
    [JsonPropertyName("client_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientUri { get; set; }

    /// <summary>
    /// URL that points to a privacy policy document.
    /// </summary>
    [JsonPropertyName("policy_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PolicyUri { get; set; }

    /// <summary>
    /// URL that points to a terms of service document.
    /// </summary>
    [JsonPropertyName("tos_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TosUri { get; set; }

    /// <summary>
    /// URL for the client's JSON Web Key Set document.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JwksUri { get; set; }

    /// <summary>
    /// Client's JSON Web Key Set document.
    /// </summary>
    [JsonPropertyName("jwks")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Jwks { get; set; }

    /// <summary>
    /// Unique identifier for the software.
    /// </summary>
    [JsonPropertyName("software_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SoftwareId { get; set; }

    /// <summary>
    /// Version identifier for the software.
    /// </summary>
    [JsonPropertyName("software_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SoftwareVersion { get; set; }

    /// <summary>
    /// Authentication method for the token endpoint.
    /// </summary>
    [JsonPropertyName("token_endpoint_auth_method")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenEndpointAuthMethod { get; set; }

    /// <summary>
    /// String containing space-separated scope values.
    /// </summary>
    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; set; }

    /// <summary>
    /// Array of post-logout redirect URIs.
    /// </summary>
    [JsonPropertyName("post_logout_redirect_uris")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? PostLogoutRedirectUris { get; set; }
}
