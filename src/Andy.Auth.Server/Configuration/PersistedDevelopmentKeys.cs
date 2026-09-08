using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Andy.Auth.Server.Configuration;

// Local, single-user Embedded mode only. Production uses ProductionKeyMaterial.
// These unencrypted PKCS#8 files rely on the desktop user's filesystem permissions.
public static class PersistedDevelopmentKeys
{
    /// <summary>
    /// Registers persisted RSA signing and encryption keys with OpenIddict.
    /// Creates <paramref name="directoryPath"/> if missing, generates
    /// keys on first call, and loads them on subsequent calls.
    /// </summary>
    /// <param name="options">The OpenIddict server options builder.</param>
    /// <param name="directoryPath">
    /// Absolute directory path that holds <c>signing.key</c> and
    /// <c>encryption.key</c>. Typically supplied via configuration
    /// (<c>OpenIddict:SigningKeys:Path</c>).
    /// </param>
    /// <returns>The builder for chaining.</returns>
    public static OpenIddictServerBuilder AddPersistedDevelopmentKeys(
        this OpenIddictServerBuilder options,
        string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            throw new ArgumentException(
                "Directory path must be non-empty.",
                nameof(directoryPath));
        }

        Directory.CreateDirectory(directoryPath);
        TrySetDirectoryPermissions(directoryPath);

        var signing = LoadOrCreate(Path.Combine(directoryPath, "signing.key"));
        var encryption = LoadOrCreate(Path.Combine(directoryPath, "encryption.key"));

        return options
            .AddSigningKey(new RsaSecurityKey(signing) { KeyId = "andy-auth-signing" })
            .AddEncryptionKey(new RsaSecurityKey(encryption) { KeyId = "andy-auth-encryption" });
    }

    // Internal for tests so the load/create round-trip can be asserted
    // directly without spinning up the OpenIddict server.
    internal static RSA LoadOrCreate(string filePath)
    {
        var rsa = RSA.Create(2048);
        if (File.Exists(filePath))
        {
            try
            {
                rsa.ImportFromPem(File.ReadAllText(filePath));
                return rsa;
            }
            catch (Exception inner) when (inner is CryptographicException
                                       || inner is ArgumentException)
            {
                // Corrupt / truncated / empty file. Refuse to regenerate
                // — auto-regenerate would invalidate every previously
                // issued JWT held by every downstream service. Surface
                // a message that names the file and tells the operator
                // exactly what to do.
                rsa.Dispose();
                throw new InvalidOperationException(
                    $"Persisted signing/encryption key at '{filePath}' is " +
                    $"corrupt or not a valid PKCS#8 PEM keypair. Refusing " +
                    $"to regenerate — that would invalidate every issued " +
                    $"JWT. Restore the file from backup, or delete it " +
                    $"intentionally to trigger a fresh keypair.",
                    inner);
            }
        }

        File.WriteAllText(filePath, rsa.ExportPkcs8PrivateKeyPem());
        TrySetFilePermissions(filePath);
        return rsa;
    }

    private static void TrySetFilePermissions(string filePath)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                filePath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (IOException)
        {
            // Filesystem does not support chmod (e.g. SMB mount).
            // Directory-level perms still gate access.
        }
        catch (UnauthorizedAccessException)
        {
            // Another process owns the file; leave perms alone.
        }
    }

    private static void TrySetDirectoryPermissions(string directoryPath)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                directoryPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
