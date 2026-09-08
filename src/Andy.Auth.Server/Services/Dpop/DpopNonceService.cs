using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Andy.Auth.Server.Services.Dpop;

public sealed class DpopNonceService(IDataProtectionProvider protection, TimeProvider clock)
{
    private readonly IDataProtector protector = protection.CreateProtector("Andy.Auth.DPoP.AS.Nonce.v1");
    public string Create(string key, TimeSpan lifetime) => protector.Protect(key + "\n" +
        clock.GetUtcNow().Add(lifetime).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) + "\n" + Guid.NewGuid().ToString("N"));
    public bool Validate(string? nonce, string key)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length > 4096) return false;
        try
        {
            var parts = protector.Unprotect(nonce).Split('\n');
            return parts.Length == 3 && parts[0] == key && long.TryParse(parts[1], CultureInfo.InvariantCulture, out var expiry) &&
                expiry > clock.GetUtcNow().ToUnixTimeSeconds();
        }
        catch (CryptographicException) { return false; }
    }
}
