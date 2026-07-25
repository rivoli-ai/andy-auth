namespace Andy.Auth.Server.Mcp;

/// <summary>
/// Builds the <c>WWW-Authenticate</c> challenge that points an MCP client at
/// this resource's RFC 9728 metadata document.
/// </summary>
/// <remarks>
/// andy-auth#155. The MCP authorization spec requires a 401 from a protected
/// resource to carry <c>resource_metadata</c> so the client can discover which
/// authorization server guards it. Composing the header is fiddlier than it
/// looks — OpenIddict's validation handler has usually already written its own
/// challenge, so this has to merge rather than overwrite or skip. An earlier
/// revision skipped whenever a header was present, which meant the pointer was
/// never emitted at all; that is why the logic lives here with tests rather
/// than inline in the pipeline.
/// </remarks>
public static class ProtectedResourceChallenge
{
    /// <summary>
    /// Returns <paramref name="existing"/> with a <c>resource_metadata</c>
    /// parameter attached, or null when it is already present and nothing needs
    /// to change.
    /// </summary>
    /// <param name="existing">
    /// The challenge already on the response, if any.
    /// </param>
    /// <param name="metadataUrl">Absolute URL of the metadata document.</param>
    public static string? Compose(string? existing, string metadataUrl)
    {
        var parameter = $"resource_metadata=\"{metadataUrl}\"";

        if (string.IsNullOrWhiteSpace(existing))
        {
            return $"Bearer {parameter}";
        }

        if (existing.Contains("resource_metadata=", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // "Bearer" on its own takes a space before its first parameter;
        // a challenge that already carries parameters takes a comma.
        var trimmed = existing.TrimEnd();
        var separator = trimmed.Equals("Bearer", StringComparison.OrdinalIgnoreCase) ? " " : ", ";
        return trimmed + separator + parameter;
    }
}
