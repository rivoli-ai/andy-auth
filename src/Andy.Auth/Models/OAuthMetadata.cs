namespace Andy.Auth.Models;

/// <summary>
/// OAuth 2.0 / OpenID Connect metadata for MCP server discovery
/// </summary>
public class OAuthMetadata
{
    /// <summary>
    /// Authorization server URL (issuer)
    /// </summary>
    public required Uri AuthorizationServer { get; init; }

    /// <summary>
    /// Dynamic Client Registration endpoint (RFC 7591)
    /// </summary>
    public Uri? RegistrationEndpoint { get; init; }

    /// <summary>
    /// Supported OAuth scopes
    /// </summary>
    public string[] ScopesSupported { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Authorization endpoint URI
    /// </summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>
    /// Token endpoint URI
    /// </summary>
    public Uri? TokenEndpoint { get; init; }
}
