using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Dpop;

public static class DpopHttpProof
{
    private static readonly object Verified = new();
    private static readonly object Failure = new();
    private sealed record Proof(string Key, string TokenHash);

    public static void Reject(HttpContext context, string error, bool unavailable = false) =>
        context.Items[Failure] = (error, unavailable);

    public static bool HasFailure(HttpContext context) => context.Items.ContainsKey(Failure);

    public static void ApplyChallenge(HttpContext context)
    {
        if (context.Items.TryGetValue(Failure, out var value) && value is ValueTuple<string, bool> failure)
        {
            context.Response.StatusCode = failure.Item2 ? 503 : 401;
            context.Response.Headers.CacheControl = "no-store";
            if (failure.Item2) context.Response.Headers.RetryAfter = "5";
            else context.Response.Headers.WWWAuthenticate = "DPoP error=\"" + failure.Item1 + "\", algs=\"ES256 RS256\"";
        }
    }

    public static async Task<bool> VerifyAsync(HttpContext context, string accessToken, TimeSpan lifetime)
    {
        if (!context.Request.IsHttps || !context.Request.Headers.TryGetValue("DPoP", out var header) || header.Count != 1)
        {
            Reject(context, "invalid_dpop_proof");
            return false;
        }
        try
        {
            var result = await context.RequestServices.GetRequiredService<DpopProofValidator>().ValidateAsync(
                header[0]!, context.Request.Method, new Uri(context.Request.GetEncodedUrl()), lifetime,
                accessToken, cancellationToken: context.RequestAborted);
            if (!result.Succeeded)
            {
                Reject(context, result.Error ?? "invalid_dpop_proof");
                return false;
            }
            context.Items[Verified] = new Proof(result.Thumbprint!, Hash(accessToken));
            return true;
        }
        catch (Exception)
        {
            Reject(context, "temporarily_unavailable", unavailable: true);
            return false;
        }
    }

    public static bool BindingSatisfied(HttpContext context, ClaimsPrincipal principal, string accessToken)
    {
        var confirmation = principal.FindAll("cnf").ToArray();
        var proof = context.Items.TryGetValue(Verified, out var value) ? value as Proof : null;
        if (confirmation.Length == 0) return proof == null; // DPoP is not a transport for an unbound bearer token
        try
        {
            if (confirmation.Length != 1 || proof == null || proof.TokenHash != Hash(accessToken)) return false;
            using var json = JsonDocument.Parse(confirmation[0].Value);
            return json.RootElement.GetProperty("jkt").GetString() == proof.Key;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException) { return false; }
    }

    private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
}
