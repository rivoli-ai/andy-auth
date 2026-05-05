using System.Security.Cryptography;
using Andy.Auth.Server.Configuration;
using FluentAssertions;

namespace Andy.Auth.Server.Tests.Configuration;

// Unit tests for PersistedDevelopmentKeys.LoadOrCreate.
//
// The invariant under test is the one that the whole Embedded-mode
// signing-key fix hinges on: calling LoadOrCreate twice against the
// same file path must return the *same* RSA key, so the JWKS served
// by andy-auth is stable across process restarts.
public class PersistedDevelopmentKeysTests : IDisposable
{
    private readonly string _tempDir;

    public PersistedDevelopmentKeysTests()
    {
        _tempDir = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-pdk-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void LoadOrCreate_GeneratesFileOnFirstCall()
    {
        var path = Path.Combine(_tempDir, "signing.key");
        File.Exists(path).Should().BeFalse("precondition");

        using var rsa = PersistedDevelopmentKeys.LoadOrCreate(path);

        File.Exists(path).Should().BeTrue("LoadOrCreate must persist the key");
        var contents = File.ReadAllText(path);
        contents.Should().Contain("BEGIN PRIVATE KEY", "PEM header expected (PKCS#8)");
        contents.Should().Contain("END PRIVATE KEY");
    }

    [Fact]
    public void LoadOrCreate_ReturnsIdenticalKeyOnSecondCall()
    {
        // This is the core invariant. If this breaks, embedded-mode
        // tokens minted in the first "boot" would be rejected in
        // the second "boot" — which is exactly the bug the helper
        // exists to prevent.
        var path = Path.Combine(_tempDir, "signing.key");

        using var first = PersistedDevelopmentKeys.LoadOrCreate(path);
        using var second = PersistedDevelopmentKeys.LoadOrCreate(path);

        var firstPem = first.ExportSubjectPublicKeyInfoPem();
        var secondPem = second.ExportSubjectPublicKeyInfoPem();

        secondPem.Should().Be(
            firstPem,
            "a second LoadOrCreate against the same path must read the " +
            "previously persisted key; otherwise JWKS rotates on every " +
            "process start and cached JWTs are invalidated.");
    }

    [Fact]
    public void LoadOrCreate_DoesNotOverwriteExistingFile()
    {
        var path = Path.Combine(_tempDir, "signing.key");
        using (var initial = PersistedDevelopmentKeys.LoadOrCreate(path)) { }

        var bytesBefore = File.ReadAllBytes(path);
        var mtimeBefore = File.GetLastWriteTimeUtc(path);

        // Sleep briefly to distinguish mtimes (filesystem resolution).
        Thread.Sleep(50);

        using (var loaded = PersistedDevelopmentKeys.LoadOrCreate(path)) { }

        var bytesAfter = File.ReadAllBytes(path);
        bytesAfter.Should().BeEquivalentTo(bytesBefore);
        File.GetLastWriteTimeUtc(path).Should().Be(mtimeBefore);
    }

    [Fact]
    public void LoadOrCreate_ProducesKeyUsableForSigning()
    {
        var path = Path.Combine(_tempDir, "signing.key");

        using var rsa = PersistedDevelopmentKeys.LoadOrCreate(path);

        var data = System.Text.Encoding.UTF8.GetBytes("embedded-mode-test");
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
           .Should().BeTrue();
    }

    [Fact]
    public void LoadOrCreate_KeyIs2048Bits()
    {
        var path = Path.Combine(_tempDir, "signing.key");
        using var rsa = PersistedDevelopmentKeys.LoadOrCreate(path);
        rsa.KeySize.Should().Be(2048);
    }

    // The extension-method surface (`AddPersistedDevelopmentKeys`) on
    // OpenIddictServerBuilder is exercised end-to-end by
    // EmbeddedModeIntegrationTests, which boots the real host and
    // verifies the JWKS stability invariant that is the whole point
    // of this helper. Narrower unit tests above (LoadOrCreate*)
    // assert the file-system contract in isolation without requiring
    // the OpenIddict.Server package reference in this test assembly.

    [Fact]
    public void LoadOrCreate_MalformedPem_ThrowsWithFilePathInMessage()
    {
        // Pins the corruption contract: a garbage PEM file must not
        // silently regenerate (regenerate = invalidate every cached
        // JWT across every downstream service). Hard-fail with the
        // path in the message so the operator knows what to fix.
        var path = Path.Combine(_tempDir, "signing.key");
        File.WriteAllText(path, "-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n");

        var act = () => PersistedDevelopmentKeys.LoadOrCreate(path);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*corrupt or not a valid PKCS#8 PEM*")
            .WithMessage($"*{path}*");
    }

    [Fact]
    public void LoadOrCreate_EmptyFile_ThrowsWithFilePathInMessage()
    {
        // First-boot interrupted between File.Create and the actual
        // PEM write leaves a zero-byte file. Same hard-fail contract
        // — don't silently regenerate.
        var path = Path.Combine(_tempDir, "signing.key");
        File.WriteAllText(path, string.Empty);

        var act = () => PersistedDevelopmentKeys.LoadOrCreate(path);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*corrupt or not a valid PKCS#8 PEM*")
            .WithMessage($"*{path}*");
    }

    [Fact]
    public void LoadOrCreate_TruncatedPem_ThrowsWithFilePathInMessage()
    {
        // Write a real key, then truncate it mid-base64 to simulate
        // a partial fsync or filesystem corruption. The truncated
        // file is not a valid keypair — must not silently regenerate.
        var path = Path.Combine(_tempDir, "signing.key");
        using (var seed = PersistedDevelopmentKeys.LoadOrCreate(path)) { }
        var full = File.ReadAllText(path);
        File.WriteAllText(path, full.Substring(0, full.Length / 2));

        var act = () => PersistedDevelopmentKeys.LoadOrCreate(path);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*corrupt or not a valid PKCS#8 PEM*")
            .WithMessage($"*{path}*");
    }

    [Fact]
    public void LoadOrCreate_UnwritableDirectory_PropagatesIoException()
    {
        // OpenIddict:SigningKeys:Path pointing at a read-only mount
        // (or a dir the service account doesn't own). Directory.CreateDirectory
        // is idempotent for an existing dir, so the failure surfaces at
        // File.WriteAllText. Skip on Windows — its ACL model differs.
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return;
        }

        var roDir = Path.Combine(_tempDir, "readonly");
        Directory.CreateDirectory(roDir);
        try
        {
            File.SetUnixFileMode(
                roDir,
                UnixFileMode.UserRead | UnixFileMode.UserExecute);

            var path = Path.Combine(roDir, "signing.key");

            var act = () => PersistedDevelopmentKeys.LoadOrCreate(path);

            act.Should().Throw<UnauthorizedAccessException>(
                "a read-only directory must surface as a permission error " +
                "so the operator can re-mount or chmod, not silently fail");
        }
        finally
        {
            // Restore write perms so xunit can clean up _tempDir.
            File.SetUnixFileMode(
                roDir,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Fact]
    public void LoadOrCreate_FilePermissionsAreOwnerOnlyOnUnix()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return; // Windows: permissions are ACL-based, checked differently.
        }

        var path = Path.Combine(_tempDir, "signing.key");
        using (var rsa = PersistedDevelopmentKeys.LoadOrCreate(path)) { }

        var mode = File.GetUnixFileMode(path);
        var groupOrOther =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        (mode & groupOrOther).Should().Be(
            UnixFileMode.None,
            "signing key file must be readable only by the owning user");
    }
}
