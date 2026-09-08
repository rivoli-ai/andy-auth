using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;

namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Explicitly provisioned, password-protected PFX bundles. All replicas must receive
/// the same version of this configuration. No key generation or deletion at startup.
/// </summary>
public sealed class ProductionKeyMaterial : IDisposable
{
    public IReadOnlyList<X509Certificate2> Signing { get; }
    public IReadOnlyList<X509Certificate2> Encryption { get; }
    public IReadOnlyList<X509Certificate2> Protection { get; }
    public string KeyRingPath { get; }
    public string ApplicationName { get; }

    private ProductionKeyMaterial(IReadOnlyList<X509Certificate2> signing,
        IReadOnlyList<X509Certificate2> encryption, IReadOnlyList<X509Certificate2> protection,
        string keyRingPath, string applicationName)
    {
        Signing = signing;
        Encryption = encryption;
        Protection = protection;
        KeyRingPath = keyRingPath;
        ApplicationName = applicationName;
    }

    public static ProductionKeyMaterial Load(IConfiguration configuration)
    {
        if (configuration.GetValue<bool>("OpenIddict:UseEphemeralKeys") ||
            !string.IsNullOrWhiteSpace(configuration["OpenIddict:SigningKeys:Path"]))
            throw new InvalidOperationException("Production requires protected certificate bundles; remove OpenIddict:SigningKeys:Path and OpenIddict:UseEphemeralKeys.");

        var loaded = new List<X509Certificate2>();
        try
        {
            var signing = LoadGroup(configuration, "OpenIddict:Certificates:Signing", loaded);
            var encryption = LoadGroup(configuration, "OpenIddict:Certificates:Encryption", loaded);
            var protection = LoadGroup(configuration, "DataProtection:Certificates", loaded);
            var now = DateTime.UtcNow;
            foreach (var group in new[] { signing, encryption })
                if (!group.Any(c => c.NotBefore.ToUniversalTime() <= now && c.NotAfter.ToUniversalTime() > now))
                    throw new InvalidOperationException("Production needs a currently valid signing and encryption certificate.");
            // Index zero encrypts new DP keys; remaining certificates decrypt retained keys.
            if (protection[0].NotBefore.ToUniversalTime() > now || protection[0].NotAfter.ToUniversalTime() <= now)
                throw new InvalidOperationException("DataProtection:Certificates:0 must be currently valid.");
            var publicKeys = loaded.Select(c => Convert.ToBase64String(c.GetPublicKey())).ToArray();
            if (publicKeys.Distinct(StringComparer.Ordinal).Count() != publicKeys.Length)
                throw new InvalidOperationException("Use distinct keys for each certificate and for signing, encryption and Data Protection.");
            var path = Required(configuration, "DataProtection:KeyRingPath");
            if (!Path.IsPathFullyQualified(path) || !Directory.Exists(path))
                throw new InvalidOperationException("DataProtection:KeyRingPath must be an existing absolute shared directory.");
            return new(signing, encryption, protection, path, Required(configuration, "DataProtection:ApplicationName"));
        }
        catch
        {
            foreach (var certificate in loaded) certificate.Dispose();
            throw;
        }
    }

    public void ConfigureDataProtection(IServiceCollection services) => services.AddDataProtection()
        .SetApplicationName(ApplicationName)
        .PersistKeysToFileSystem(new DirectoryInfo(KeyRingPath))
        .ProtectKeysWithCertificate(Protection[0])
        .UnprotectKeysWithAnyCertificate(Protection.ToArray());

    private static X509Certificate2[] LoadGroup(IConfiguration configuration, string section,
        List<X509Certificate2> loaded)
    {
        var entries = configuration.GetSection(section).GetChildren().ToArray();
        if (entries.Length == 0)
            throw new InvalidOperationException($"Production requires {section} certificate entries.");
        return entries.Select(entry =>
        {
            var path = Required(entry, "Path");
            var password = Required(entry, "Password");
            if (!Path.IsPathFullyQualified(path))
                throw new InvalidOperationException($"{entry.Path}:Path must be absolute.");
            // A PFX MAC/password alone is not private-key encryption. Reject raw
            // key bags in unencrypted safe contents, even in MAC-protected files.
            var bundle = Pkcs12Info.Decode(File.ReadAllBytes(path), out _);
            foreach (var contents in bundle.AuthenticatedSafe)
                if (contents.ConfidentialityMode == Pkcs12ConfidentialityMode.None &&
                    contents.GetBags().Any(bag => bag is Pkcs12KeyBag))
                    throw new InvalidOperationException($"{entry.Path} contains an unencrypted private key.");
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password, (OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet));
            loaded.Add(certificate);
            // Reject bundles that can be opened without a password, even when a
            // nonempty password was supplied in configuration.
            var unprotected = false;
            try
            {
                using var probe = X509CertificateLoader.LoadPkcs12FromFile(path, "", (OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet));
                unprotected = true;
            }
            catch (CryptographicException) { }
            if (unprotected)
                throw new InvalidOperationException($"{entry.Path} must be a password-protected PFX bundle.");
            using var rsa = certificate.GetRSAPrivateKey();
            if (rsa is null || rsa.KeySize < 2048)
                throw new InvalidOperationException($"{entry.Path} must contain an RSA private key of at least 2048 bits.");
            return certificate;
        }).ToArray();
    }

    private static string Required(IConfiguration configuration, string key) =>
        !string.IsNullOrWhiteSpace(configuration[key]) ? configuration[key]! :
            throw new InvalidOperationException($"Production requires {configuration.GetSection(key).Path}.");

    public void Dispose()
    {
        foreach (var certificate in Signing.Concat(Encryption).Concat(Protection)) certificate.Dispose();
    }
}
