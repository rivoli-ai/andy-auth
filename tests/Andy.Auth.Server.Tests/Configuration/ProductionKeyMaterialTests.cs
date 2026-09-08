using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Andy.Auth.Server.Tests.Configuration;

public sealed class ProductionKeyMaterialTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "andy-protected-" + Guid.NewGuid().ToString("N"));
    public void Dispose() => Directory.Delete(_directory, true);

    [Theory]
    [InlineData("OpenIddict:Certificates:Signing:0:Password", "")]
    [InlineData("OpenIddict:Certificates:Signing:0:Password", "wrong")]
    [InlineData("DataProtection:KeyRingPath", "relative")]
    [InlineData("DataProtection:ApplicationName", "")]
    public void InvalidProtectionFailsClosed(string key, string value)
    {
        var fixture = new ProductionKeyFixture(_directory);
        fixture.Values[key] = value;
        var act = () => ProductionKeyMaterial.Load(fixture.Configuration);
        act.Should().Throw<Exception>();
    }

    [Fact]
    public void MacProtectedButUnencryptedPrivateKeyIsRejected()
    {
        var fixture = new ProductionKeyFixture(_directory);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=unencrypted", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var contents = new Pkcs12SafeContents();
        contents.AddCertificate(certificate);
        contents.AddKeyUnencrypted(rsa);
        var builder = new Pkcs12Builder();
        builder.AddSafeContentsUnencrypted(contents);
        builder.SealWithMac(ProductionKeyFixture.Password, HashAlgorithmName.SHA256, 10000);
        File.WriteAllBytes(fixture.Values["OpenIddict:Certificates:Signing:0:Path"]!, builder.Encode());
        var act = () => ProductionKeyMaterial.Load(fixture.Configuration);
        act.Should().Throw<InvalidOperationException>().WithMessage("*unencrypted private key*");
    }

    [Fact]
    public void ExpiredOnlySigningGroupIsRejected()
    {
        var fixture = new ProductionKeyFixture(_directory);
        fixture.Add("OpenIddict:Certificates:Signing:0", "expired", DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        var act = () => ProductionKeyMaterial.Load(fixture.Configuration);
        act.Should().Throw<InvalidOperationException>().WithMessage("*currently valid signing*");
    }

    [Fact]
    public void ReplicasAndRestartsDecryptCookies_AfterProtectionCertificateRotationAndRestore()
    {
        var fixture = new ProductionKeyFixture(_directory);
        using var originalKeys = ProductionKeyMaterial.Load(fixture.Configuration);
        using var first = Provider(originalKeys);
        var cookie = first.GetDataProtector("cookie-test").Protect("user-session");
        var ring = fixture.Values["DataProtection:KeyRingPath"]!;
        var backup = Directory.GetFiles(ring).ToDictionary(Path.GetFileName, File.ReadAllBytes);
        File.ReadAllText(Directory.GetFiles(ring).Single()).Should().Contain("encryptedSecret");

        fixture.Values["DataProtection:Certificates:1:Path"] = fixture.Values["DataProtection:Certificates:0:Path"];
        fixture.Values["DataProtection:Certificates:1:Password"] = ProductionKeyFixture.Password;
        fixture.Add("DataProtection:Certificates:0", "protection-next", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
        using var rotatedKeys = ProductionKeyMaterial.Load(fixture.Configuration);
        using var second = Provider(rotatedKeys);
        second.GetDataProtector("cookie-test").Unprotect(cookie).Should().Be("user-session");
        second.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var third = Provider(rotatedKeys);
        var newCookie = third.GetDataProtector("cookie-test").Protect("rotated-session");
        using var fourth = Provider(rotatedKeys);
        fourth.GetDataProtector("cookie-test").Unprotect(newCookie).Should().Be("rotated-session");

        foreach (var file in Directory.GetFiles(ring)) File.Delete(file);
        foreach (var (name, bytes) in backup) File.WriteAllBytes(Path.Combine(ring, name!), bytes);
        using var restored = Provider(rotatedKeys);
        restored.GetDataProtector("cookie-test").Unprotect(cookie).Should().Be("user-session");
    }

    [Fact]
    public async Task OverlapSelectsNewSigningKey_AndValidatesPreviouslyIssuedToken()
    {
        var fixture = new ProductionKeyFixture(_directory);
        using var before = ProductionKeyMaterial.Load(fixture.Configuration);
        var handler = new JsonWebTokenHandler();
        var jwt = handler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("sub", "test-user") }),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new X509SecurityKey(before.Signing[0]), SecurityAlgorithms.RsaSha256)
        });
        fixture.Add("OpenIddict:Certificates:Signing:1", "signing-next", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
        using var after = ProductionKeyMaterial.Load(fixture.Configuration);
        using var services = OpenIddictProvider(after);
        var options = services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        options.SigningCredentials[0].Key.KeyId.Should().Be(new X509SecurityKey(after.Signing[1]).KeyId);
        var validation = await handler.ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            ValidateIssuer = false, ValidateAudience = false,
            IssuerSigningKeys = options.SigningCredentials.Select(c => c.Key)
        });
        validation.IsValid.Should().BeTrue();
        after.Signing.Select(c => c.Thumbprint).Distinct().Should().HaveCount(2);
    }

    [Fact]
    public void FutureCertificateIsRetainedButNotSelectedForIssuance()
    {
        var fixture = new ProductionKeyFixture(_directory);
        fixture.Add("OpenIddict:Certificates:Signing:1", "future", DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow.AddDays(60));
        using var keys = ProductionKeyMaterial.Load(fixture.Configuration);
        using var services = OpenIddictProvider(keys);
        var options = services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        options.SigningCredentials.Should().HaveCount(2);
        options.SigningCredentials[0].Key.KeyId.Should().Be(new X509SecurityKey(keys.Signing[0]).KeyId);
    }

    private static ServiceProvider Provider(ProductionKeyMaterial keys)
    {
        var services = new ServiceCollection().AddLogging();
        keys.ConfigureDataProtection(services);
        return services.BuildServiceProvider();
    }

    private static ServiceProvider OpenIddictProvider(ProductionKeyMaterial keys)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddOpenIddict().AddServer(options =>
        {
            options.SetTokenEndpointUris("/token").AllowClientCredentialsFlow().EnableDegradedMode();
            // No HTTP requests are sent by this options-selection test.
            options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(
                handler => handler.UseInlineHandler(_ => default));
            foreach (var certificate in keys.Signing) options.AddSigningCertificate(certificate);
            foreach (var certificate in keys.Encryption) options.AddEncryptionCertificate(certificate);
        });
        return services.BuildServiceProvider();
    }
}
