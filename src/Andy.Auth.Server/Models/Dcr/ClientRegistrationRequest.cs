using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Models.Dcr;

/// <summary>
/// Client registration request per RFC 7591 Section 2.
/// </summary>
public class ClientRegistrationRequest
{
    /// <summary>
    /// Array of redirect URIs for use in redirect-based flows.
    /// Required for authorization_code grant type.
    /// </summary>
    [JsonPropertyName("redirect_uris")]
    public List<string>? RedirectUris { get; set; }

    /// <summary>
    /// JSON array containing OAuth 2.0 response_type values.
    /// </summary>
    [JsonPropertyName("response_types")]
    public List<string>? ResponseTypes { get; set; }

    /// <summary>
    /// JSON array containing OAuth 2.0 grant_type values.
    /// </summary>
    [JsonPropertyName("grant_types")]
    public List<string>? GrantTypes { get; set; }

    /// <summary>
    /// Kind of the application (web, native, or service).
    /// </summary>
    [JsonPropertyName("application_type")]
    public string? ApplicationType { get; set; }

    /// <summary>
    /// Array of email addresses of people responsible for this client.
    /// </summary>
    [JsonPropertyName("contacts")]
    public List<string>? Contacts { get; set; }

    /// <summary>
    /// Human-readable name of the client.
    /// </summary>
    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    /// <summary>
    /// URL that references a logo for the client.
    /// </summary>
    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; set; }

    /// <summary>
    /// URL of the home page of the client.
    /// </summary>
    [JsonPropertyName("client_uri")]
    public string? ClientUri { get; set; }

    /// <summary>
    /// URL that points to a human-readable privacy policy document.
    /// </summary>
    [JsonPropertyName("policy_uri")]
    public string? PolicyUri { get; set; }

    /// <summary>
    /// URL that points to a human-readable terms of service document.
    /// </summary>
    [JsonPropertyName("tos_uri")]
    public string? TosUri { get; set; }

    /// <summary>
    /// URL for the client's JSON Web Key Set document.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; set; }

    /// <summary>
    /// Client's JSON Web Key Set document.
    /// </summary>
    [JsonPropertyName("jwks")]
    public string? Jwks { get; set; }

    /// <summary>
    /// Unique identifier for the software comprising the client.
    /// </summary>
    [JsonPropertyName("software_id")]
    public string? SoftwareId { get; set; }

    /// <summary>
    /// Version identifier for the software comprising the client.
    /// </summary>
    [JsonPropertyName("software_version")]
    public string? SoftwareVersion { get; set; }

    /// <summary>
    /// A software statement containing client metadata values.
    /// </summary>
    [JsonPropertyName("software_statement")]
    public string? SoftwareStatement { get; set; }

    /// <summary>
    /// Requested authentication method for the token endpoint.
    /// </summary>
    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; }

    /// <summary>
    /// String containing space-separated scope values.
    /// </summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    /// <summary>
    /// Array of post-logout redirect URIs.
    /// </summary>
    [JsonPropertyName("post_logout_redirect_uris")]
    public List<string>? PostLogoutRedirectUris { get; set; }
}
