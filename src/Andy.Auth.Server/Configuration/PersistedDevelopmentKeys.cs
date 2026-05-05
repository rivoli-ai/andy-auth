using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Andy.Auth.Server.Configuration;

// File-backed signing + encryption keys for deployment modes where the
// server restarts frequently but clients hold long-lived tokens across
// restarts (specifically: Conductor embedded mode).
//
// AddEphemeralSigningKey()/AddEphemeralEncryptionKey() generate keys
// in memory and rotate them on every process start. That is fine for
// `dotnet run` development (browser clients reauthenticate on reload)
// but catastrophic when the same server is bundled inside a desktop
// app that the user relaunches frequently — every relaunch invalidates
// every previously-minted JWT and every downstream service starts
// returning 401 until a token refresh races through.
//
// This helper persists a 2048-bit RSA keypair as unencrypted PKCS#8
// PEM to `<directoryPath>/signing.key` and `<directoryPath>/encryption.key`.
// On first boot the keys are generated and written; on subsequent
// boots they are loaded verbatim so the JWKS `kid` stays constant.
//
// Security model: the keys protect a local, single-user session
// inside a desktop app. Directory+file permissions (0700/0600 on
// Unix) gate access to the owning user. This is intentionally not
// a replacement for the production X.509 certificate path, which
// remains the correct choice for hosted multi-tenant deployments.
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
            rsa.ImportFromPem(File.ReadAllText(filePath));
            return rsa;
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
