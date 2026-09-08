using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Moves validated PAR consent metadata through encrypted TempData, never through
/// unprotected browser parameters. The actual request remains in OpenIddict's store.
/// </summary>
public sealed record ParConsentContext(string Subject, string ClientId, string? RedirectUri,
    string[] Scopes, DateTime ExpiresAt)
{
    private static string Key(string requestUri) => "par-consent:" +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(requestUri)));

    public static void Capture(ITempDataDictionary data, string requestUri, string subject,
        OpenIddictRequest request)
    {
        data[Key(requestUri)] = JsonSerializer.Serialize(new ParConsentContext(subject,
            request.ClientId!, request.RedirectUri, request.GetScopes().ToArray(), DateTime.UtcNow.AddMinutes(10)));
    }

    public static Dictionary<string, StringValues>? Resolve(ITempDataDictionary data,
        Dictionary<string, StringValues> query, string? subject)
    {
        if (!query.TryGetValue("request_uri", out var uri)) return query;
        if (uri.Count != 1 || string.IsNullOrEmpty(uri[0])) return null;
        var json = data.Peek(Key(uri[0]!)) as string;
        if (json is null) return null;
        var context = JsonSerializer.Deserialize<ParConsentContext>(json);
        if (context is null || context.Subject != subject || context.ExpiresAt <= DateTime.UtcNow ||
            (!query.TryGetValue("client_id", out var client) || client.ToString() != context.ClientId)) return null;
        // Replace only from authenticated server metadata. Extra browser scope and
        // redirect parameters cannot enlarge the displayed or approved request.
        query["scope"] = string.Join(" ", context.Scopes);
        query["redirect_uri"] = context.RedirectUri;
        return query;
    }

    // Prefix avoids TempData's serializer interpreting a GUID-shaped subject as
    // a Guid value rather than a string on the next request.
    public static void Deny(ITempDataDictionary data, string uri, string subject) =>
        data[Key(uri) + ":denied"] = "subject:" + subject;

    public static bool ConsumeDenial(ITempDataDictionary data, string uri, string subject) =>
        data[Key(uri) + ":denied"] as string == "subject:" + subject;
}
