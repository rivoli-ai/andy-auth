using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Andy.Auth.ServiceCertificates;

public sealed record ServiceCertificateValidation(string? Identity, string? Subject, string? Error, bool Unavailable = false)
{
    public bool Succeeded => Error is null && Identity is not null;
}

/// <summary>Validates a TLS peer against explicit private roots and registered URI SAN identity.</summary>
public sealed class ServiceCertificateValidator(IOptionsMonitor<ServiceCertificateOptions> configuration,
    IHostEnvironment environment, TimeProvider clock)
{
    public ServiceCertificateValidation Validate(X509Certificate2 certificate, string? expectedServerIdentity = null)
        => ValidateCore(certificate, expectedServerIdentity, expectedServerIdentity is not null);

    public ServiceCertificateValidation ValidateLocal(X509Certificate2 certificate, string identity)
        => ValidateCore(certificate, identity, false);

    private ServiceCertificateValidation ValidateCore(X509Certificate2 certificate, string? expectedIdentity, bool server)
    {
        var options = configuration.CurrentValue;
        try
        {
            if (!options.IsValid()) return new(null, null, "invalid_certificate_configuration", true);
            if (options.AllowDevelopmentNoRevocation && !environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
                return new(null, null, "revocation_checks_required", true);
            if (certificate.RawData.Length > 32768 || certificate.NotAfter.ToUniversalTime() - certificate.NotBefore.ToUniversalTime() > options.MaximumLeafLifetime)
                return Invalid("certificate_lifetime");
            var now = clock.GetUtcNow().UtcDateTime;
            if (certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() <= now) return Invalid("certificate_expired_or_not_yet_valid");
            var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
            if (constraints is null || constraints.CertificateAuthority) return Invalid("ca_certificate_is_not_a_service");
            var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            if (usage == null || !usage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)) return Invalid("certificate_key_usage");
            var purposes = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            var requiredPurpose = !server ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1";
            if (purposes == null || !purposes.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == requiredPurpose)) return Invalid("certificate_purpose");
            using var rsa = certificate.GetRSAPublicKey();
            using var ec = certificate.GetECDsaPublicKey();
            if (certificate.SignatureAlgorithm.Value is "1.2.840.113549.1.1.5" or "1.2.840.10045.4.1") return Invalid("weak_certificate_signature");
            if (rsa is not null ? rsa.KeySize < 2048 : ec is null || ec.KeySize < 256) return Invalid("certificate_key_strength");
            var identity = ReadServiceIdentity(certificate);
            if (identity == null) return Invalid("certificate_service_identity");
            string? subject;
            if (expectedIdentity != null)
            {
                if (!ServiceCertificateOptions.IsServiceIdentity(expectedIdentity) || identity != expectedIdentity)
                    return Invalid("wrong_server_identity");
                subject = identity;
            }
            else if (!options.AllowedClientIdentities.TryGetValue(identity, out subject)) return Invalid("unregistered_service");

            var bundleText = ReadBounded(options.TrustBundlePath);
            var bundle = new X509Certificate2Collection();
            bundle.ImportFromPem(bundleText);
            try
            {
                if (bundle.Count == 0) return new(null, null, "empty_trust_bundle", true);
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.VerificationTime = now;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(3);
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid(requiredPurpose));
                var trustedIntermediates = new HashSet<string>(StringComparer.Ordinal);
                foreach (var issuer in bundle)
                {
                    if (issuer.HasPrivateKey || issuer.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true)
                        return new(null, null, "invalid_ca_bundle", true);
                    if (issuer.SubjectName.RawData.AsSpan().SequenceEqual(issuer.IssuerName.RawData)) chain.ChainPolicy.CustomTrustStore.Add(issuer);
                    else { chain.ChainPolicy.ExtraStore.Add(issuer); trustedIntermediates.Add(issuer.Thumbprint); }
                }
                if (chain.ChainPolicy.CustomTrustStore.Count == 0) return new(null, null, "missing_trust_root", true);
                // Establish trust without network fetches before allowing a CRL lookup.
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (!chain.Build(certificate) || !PinnedIntermediates(chain, trustedIntermediates)) return Invalid("untrusted_certificate");
                if (!options.AllowDevelopmentNoRevocation)
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    // Service-leaf revocation is online. Intermediate removal is enforced
                    // by the explicit bundle pin above, independently of OS issuer caches.
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                    if (!chain.Build(certificate))
                    {
                        var unavailable = chain.ChainStatus.Any(status => (status.Status & (X509ChainStatusFlags.OfflineRevocation | X509ChainStatusFlags.RevocationStatusUnknown)) != 0);
                        return new(null, null, unavailable ? "revocation_unavailable" : "revoked_certificate", unavailable);
                    }
                }
                if (!PinnedIntermediates(chain, trustedIntermediates)) return Invalid("untrusted_certificate");
                return new(identity, subject, null);
            }
            finally { foreach (var issuer in bundle) issuer.Dispose(); }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { return new(null, null, "certificate_trust_unavailable", true); }
        catch (Exception error) when (error is CryptographicException or AsnContentException or ArgumentException or InvalidOperationException)
        { return Invalid("invalid_certificate"); }
    }

    private static bool PinnedIntermediates(X509Chain chain, HashSet<string> trusted) =>
        chain.ChainElements.Cast<X509ChainElement>().Skip(1).SkipLast(1).All(element => trusted.Contains(element.Certificate.Thumbprint));

    internal static string ReadBounded(string path)
    {
        using var file = File.OpenRead(path);
        if (file.Length > 1024 * 1024) throw new IOException("Certificate material exceeds its size limit.");
        using var reader = new StreamReader(file);
        var buffer = new char[1024 * 1024 + 1];
        var length = reader.ReadBlock(buffer, 0, buffer.Length);
        if (length > 1024 * 1024) throw new IOException("Certificate material exceeds its size limit.");
        return new string(buffer, 0, length);
    }

    public static string? ReadServiceIdentity(X509Certificate2 certificate)
    {
        var extensions = certificate.Extensions.Cast<X509Extension>().Where(extension => extension.Oid?.Value == "2.5.29.17").ToArray();
        if (extensions.Length != 1) return null;
        var reader = new AsnReader(extensions[0].RawData, AsnEncodingRules.DER);
        var names = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        var identities = new List<string>();
        while (names.HasData)
        {
            var tag = names.PeekTag();
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
                identities.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, tag));
            else names.ReadEncodedValue();
        }
        return identities.Count == 1 && ServiceCertificateOptions.IsServiceIdentity(identities[0]) ? identities[0] : null;
    }

    private static ServiceCertificateValidation Invalid(string error) => new(null, null, error);
}
