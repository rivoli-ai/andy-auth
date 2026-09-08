using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Andy.Auth.Server.Services.Ciba;

public sealed class CibaOptions
{
    public const string GrantType = "urn:openid:params:grant-type:ciba";
    public const string DeliveryModeProperty = "backchannel_token_delivery_mode";
    public bool Enabled { get; set; }
    public TimeSpan AuthenticationLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(5);
    public string VapidPublicKey { get; set; } = "";
    public string VapidPrivateKey { get; set; } = "";
    public string VapidSubject { get; set; } = "";
    public string[] PushOrigins { get; set; } = ["https://fcm.googleapis.com", "https://updates.push.services.mozilla.com", "https://web.push.apple.com"];

    public bool IsValid()
    {
        if (AuthenticationLifetime < TimeSpan.FromSeconds(30) || AuthenticationLifetime > TimeSpan.FromMinutes(10) ||
            PollingInterval < TimeSpan.FromSeconds(5) || PollingInterval > TimeSpan.FromSeconds(30)) return false;
        if (!Enabled) return true;
        try
        {
            var publicKey = Base64UrlEncoder.DecodeBytes(VapidPublicKey);
            var privateKey = Base64UrlEncoder.DecodeBytes(VapidPrivateKey);
            if (publicKey.Length != 65 || publicKey[0] != 4 || privateKey.Length != 32) return false;
            using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = publicKey[1..33], Y = publicKey[33..65] }, D = privateKey });
            if (!key.VerifyData(new byte[] { 1, 2, 3 }, key.SignData(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256)) return false;
            return Uri.TryCreate(VapidSubject, UriKind.Absolute, out var subject) && subject.Scheme is "https" or "mailto" &&
                PushOrigins.Length > 0 && PushOrigins.All(origin => Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
                    uri.Scheme == "https" && uri.AbsolutePath == "/" && uri.UserInfo == "" && uri.Query == "" && uri.Fragment == "");
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException or FormatException) { return false; }
    }

    public bool AllowsEndpoint(string endpoint) => Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) &&
        endpoint.Length <= 2048 && uri.Scheme == "https" && uri.UserInfo == "" && uri.Fragment == "" &&
        PushOrigins.Any(origin => Uri.Compare(new Uri(origin), new Uri(uri.GetLeftPart(UriPartial.Authority)),
            UriComponents.SchemeAndServer, UriFormat.UriEscaped, StringComparison.OrdinalIgnoreCase) == 0);
}
