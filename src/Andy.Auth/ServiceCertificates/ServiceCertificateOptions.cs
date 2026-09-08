namespace Andy.Auth.ServiceCertificates;

public enum ServiceAuthenticationMode { Jwt, Both, ClientCertificate }

/// <summary>Private-PKI service authentication; user OIDC remains a separate scheme.</summary>
public sealed class ServiceCertificateOptions
{
    public const string SectionName = "Auth";
    public ServiceAuthenticationMode Mode { get; set; } = ServiceAuthenticationMode.Jwt;
    public bool RequireClientCertificate { get; set; }
    public string JwtScheme { get; set; } = "Bearer";
    public string TrustBundlePath { get; set; } = "";
    public string CertificatePath { get; set; } = "";
    public string? PrivateKeyPath { get; set; }
    public string LocalServiceIdentity { get; set; } = "";
    public string ExpectedServerIdentity { get; set; } = "";
    public Dictionary<string, string> AllowedClientIdentities { get; set; } = new(StringComparer.Ordinal);
    public string SubjectProvider { get; set; } = "andy-auth";
    public bool AllowDevelopmentNoRevocation { get; set; }
    public TimeSpan MaximumLeafLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public ServiceAuthenticationMode EffectiveMode => RequireClientCertificate ? ServiceAuthenticationMode.ClientCertificate : Mode;

    public bool IsValid() => Enum.IsDefined(Mode) && !string.IsNullOrWhiteSpace(JwtScheme) && JwtScheme is not ServiceCertificateAuthentication.Scheme and not ServiceCertificateAuthentication.CertificateScheme &&
        !string.IsNullOrWhiteSpace(SubjectProvider) && SubjectProvider.Length <= 256 && !SubjectProvider.Any(char.IsControl) &&
        MaximumLeafLifetime >= TimeSpan.FromMinutes(1) && MaximumLeafLifetime <= TimeSpan.FromMinutes(10) &&
        (EffectiveMode == ServiceAuthenticationMode.Jwt || !string.IsNullOrWhiteSpace(TrustBundlePath)) &&
        AllowedClientIdentities.All(pair => IsServiceIdentity(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value) && pair.Value.Length <= 256 && !pair.Value.Any(char.IsControl));

    public static bool IsServiceIdentity(string value) => value.Length <= 256 && value.StartsWith("urn:", StringComparison.Ordinal) &&
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == "urn" && !value.Any(char.IsWhiteSpace) && !value.Any(char.IsControl);
}
