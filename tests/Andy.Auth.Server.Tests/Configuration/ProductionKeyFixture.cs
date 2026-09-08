using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;

namespace Andy.Auth.Server.Tests.Configuration;

internal sealed class ProductionKeyFixture
{
    public const string Password = "test-only-protected-pfx-password";
    public Dictionary<string, string?> Values { get; } = new();
    public string DirectoryPath { get; }
    public IConfiguration Configuration => new ConfigurationBuilder().AddInMemoryCollection(Values).Build();

    public ProductionKeyFixture(string directory)
    {
        DirectoryPath = directory;
        Directory.CreateDirectory(directory);
        var now = DateTimeOffset.UtcNow;
        Add("OpenIddict:Certificates:Signing:0", "signing", now.AddDays(-1), now.AddDays(30));
        Add("OpenIddict:Certificates:Encryption:0", "encryption", now.AddDays(-1), now.AddDays(30));
        Add("DataProtection:Certificates:0", "protection", now.AddDays(-1), now.AddDays(30));
        var ring = Path.Combine(directory, "ring");
        Directory.CreateDirectory(ring);
        Values["DataProtection:KeyRingPath"] = ring;
        Values["DataProtection:ApplicationName"] = "andy-auth-tests";
    }

    public void Add(string section, string name, DateTimeOffset start, DateTimeOffset end)
    {
        var path = Path.Combine(DirectoryPath, name + ".pfx");
        if (!File.Exists(path))
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(start, end);
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, Password));
        }
        Values[section + ":Path"] = path;
        Values[section + ":Password"] = Password;
    }
}
