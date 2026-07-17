using Microsoft.AspNetCore.Http;

namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Per-request Content-Security-Policy nonce (issue #128). The security-headers
/// middleware generates a fresh value per request, stashes it in
/// <see cref="HttpContext.Items"/>, and emits it into the CSP header;
/// <c>NonceTagHelper</c> then stamps the same value onto every inline
/// <c>&lt;script&gt;</c>/<c>&lt;style&gt;</c> element so the Razor views execute
/// under a nonce-based policy instead of <c>'unsafe-inline'</c>.
/// </summary>
public static class CspNonce
{
    /// <summary>Key under which the nonce is stored in <see cref="HttpContext.Items"/>.</summary>
    public const string HttpContextItemKey = "CspNonce";

    /// <summary>Returns the current request's CSP nonce, or <c>null</c> when CSP is disabled.</summary>
    public static string? Get(HttpContext context) =>
        context.Items.TryGetValue(HttpContextItemKey, out var value) ? value as string : null;
}
