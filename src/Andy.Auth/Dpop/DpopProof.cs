using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Andy.Auth.Dpop;

public sealed class DpopOptions
{
    public bool Enabled { get; set; }
    public bool RequireNonce { get; set; } = true;
    public TimeSpan ProofLifetime { get; set; } = TimeSpan.FromMinutes(1);
}

public interface IDpopReplayStore
{
    /// <summary>Atomically reserve a proof identifier across all validating replicas.</summary>
    Task<bool> TryUseAsync(string thumbprint, string id, TimeSpan retention, CancellationToken cancellationToken);
}

public sealed record DpopValidation(string? Thumbprint, string? Error)
{
    public bool Succeeded => Error is null && Thumbprint is not null;
}

public sealed class DpopProofValidator(IDpopReplayStore replays, TimeProvider clock)
{
    public async Task<DpopValidation> ValidateAsync(string proof, string method, Uri target, TimeSpan lifetime,
        string? accessToken = null, Func<string?, string, bool>? nonceValidator = null, CancellationToken cancellationToken = default)
    {
        string thumbprint;
        string id;
        try
        {
            if (string.IsNullOrWhiteSpace(proof) || proof.Length > 16384 || lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(5))
                return Invalid();
            var parts = proof.Split('.');
            if (parts.Length != 3) return Invalid();
            using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[0]));
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]));
            if (header.RootElement.ValueKind != JsonValueKind.Object || payload.RootElement.ValueKind != JsonValueKind.Object ||
                DuplicateNames(header.RootElement) || DuplicateNames(payload.RootElement)) return Invalid();
            var h = header.RootElement;
            var p = payload.RootElement;
            if (h.GetProperty("typ").GetString() != "dpop+jwt" ||
                h.TryGetProperty("crit", out _) || h.TryGetProperty("jku", out _) || h.TryGetProperty("x5u", out _) || h.TryGetProperty("x5c", out _)) return Invalid();
            var alg = h.GetProperty("alg").GetString();
            var jwkJson = h.GetProperty("jwk");
            if (jwkJson.ValueKind != JsonValueKind.Object || DuplicateNames(jwkJson) ||
                new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" }.Any(name => jwkJson.TryGetProperty(name, out _))) return Invalid();
            var jwk = new JsonWebKey(jwkJson.GetRawText());
            if (alg == SecurityAlgorithms.EcdsaSha256)
            {
                if (jwk.Kty != "EC" || jwk.Crv != "P-256" || Base64UrlEncoder.DecodeBytes(jwk.X).Length != 32 ||
                    Base64UrlEncoder.DecodeBytes(jwk.Y).Length != 32) return Invalid();
            }
            else if (alg == SecurityAlgorithms.RsaSha256)
            {
                if (jwk.Kty != "RSA") return Invalid();
                var modulus = Base64UrlEncoder.DecodeBytes(jwk.N);
                if (modulus.Length is < 256 or > 512 || modulus[0] == 0 || modulus.Length == 256 && modulus[0] < 128)
                    return Invalid();
            }
            else return Invalid();
            var validated = await new JsonWebTokenHandler().ValidateTokenAsync(proof, new TokenValidationParameters
            {
                ValidateIssuer = false, ValidateAudience = false, RequireExpirationTime = false, ValidateLifetime = false,
                RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKey = jwk,
                ValidTypes = new[] { "dpop+jwt" }, ValidAlgorithms = new[] { SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.RsaSha256 }
            });
            if (!validated.IsValid || p.GetProperty("htm").GetString() != method) return Invalid();
            if (!Uri.TryCreate(p.GetProperty("htu").GetString(), UriKind.Absolute, out var htu) ||
                htu.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(htu.UserInfo) ||
                !string.IsNullOrEmpty(htu.Query) || !string.IsNullOrEmpty(htu.Fragment) ||
                CanonicalTarget(htu) != CanonicalTarget(target)) return Invalid();
            var now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (!p.GetProperty("iat").TryGetInt64(out var issued) || issued < now - (long)lifetime.TotalSeconds || issued > now + 10)
                return Invalid();
            id = p.GetProperty("jti").GetString()!;
            if (string.IsNullOrWhiteSpace(id) || id.Length > 256 || id.Any(char.IsControl)) return Invalid();
            thumbprint = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
            if (accessToken is not null && (!p.TryGetProperty("ath", out var ath) ||
                ath.GetString() != Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))))) return Invalid();
            var nonce = p.TryGetProperty("nonce", out var nonceClaim) ? nonceClaim.GetString() : null;
            if (nonceValidator is not null && !nonceValidator(nonce, thumbprint))
                return new(thumbprint, "use_dpop_nonce");

        }
        catch (Exception error) when (error is ArgumentException or JsonException or KeyNotFoundException or
            InvalidOperationException or FormatException or CryptographicException or SecurityTokenException)
        {
            return Invalid();
        }
        // Backend failures must remain distinguishable from a malformed proof.
        if (!await replays.TryUseAsync(thumbprint, id, lifetime + TimeSpan.FromSeconds(10), cancellationToken)) return Invalid();
        return new(thumbprint, null);
    }

    public static string CanonicalTarget(Uri uri) => uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
    private static bool DuplicateNames(JsonElement value) => value.EnumerateObject().GroupBy(property => property.Name, StringComparer.Ordinal).Any(group => group.Count() > 1);
    private static DpopValidation Invalid() => new(null, "invalid_dpop_proof");
}

/// <summary>Creates a fresh proof using a caller-owned key; private JWK fields are never sent.</summary>
public static class DpopProof
{
    public static string Create(SigningCredentials credentials, string method, Uri target, string? accessToken = null,
        string? nonce = null, DateTimeOffset? issuedAt = null)
    {
        var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(credentials.Key);
        var publicKey = jwk.Kty switch
        {
            "RSA" => new Dictionary<string, object> { ["kty"] = "RSA", ["n"] = jwk.N, ["e"] = jwk.E },
            "EC" => new Dictionary<string, object> { ["kty"] = "EC", ["crv"] = jwk.Crv, ["x"] = jwk.X, ["y"] = jwk.Y },
            _ => throw new ArgumentException("DPoP requires an asymmetric RSA or EC key.")
        };
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)),
            ["htm"] = method, ["htu"] = DpopProofValidator.CanonicalTarget(target)
        };
        if (accessToken != null) claims["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        if (nonce != null) claims["nonce"] = nonce;
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "dpop+jwt", SigningCredentials = credentials, IssuedAt = (issuedAt ?? DateTimeOffset.UtcNow).UtcDateTime,
            Claims = claims, AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = publicKey }
        });
    }
}
