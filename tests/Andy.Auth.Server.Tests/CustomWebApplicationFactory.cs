using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Shared <see cref="WebApplicationFactory{TEntryPoint}"/> for integration tests.
///
/// The factory is fully hermetic: it never touches a developer-local
/// PostgreSQL. Instead it points the app at an isolated, per-instance SQLite
/// file and supplies the OAuth clients the tests need as a fixture manifest.
/// This is what lets the suite pass from a clean checkout with no external
/// database running.
///
/// Why environment variables (not <c>ConfigureAppConfiguration</c>): Program.cs
/// reads <c>builder.Configuration</c> (DB provider, connection string,
/// manifest paths) while building the host — before WebApplicationFactory's
/// <c>ConfigureAppConfiguration</c> callbacks run. ASP.NET Core's
/// EnvironmentVariablesConfigurationProvider maps <c>Key__SubKey=Value</c> to
/// <c>Key:SubKey=Value</c> and is visible from the very first configuration
/// read, so environment variables are the only reliable injection point.
///
/// Every variable set here is captured and restored on <see cref="Dispose"/>
/// (scoped restoration — no permanent process-wide mutation), and the SQLite
/// file is deleted. Tests in this assembly run serially
/// (<c>xunit.runner.json</c>: parallelizeTestCollections/Assembly = false), so
/// only one factory's environment is live at a time.
/// </summary>
public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    /// <summary>Seeded admin (Admin role) — password injected below.</summary>
    public const string AdminEmail = "admin@andy-auth.local";
    public const string AdminPassword = "AdminTest123!";

    /// <summary>Seeded test user (User role), created in Development.</summary>
    public const string TestUserEmail = "test@andy.local";
    public const string TestUserPassword = "Test123!";

    /// <summary>The well-known Development-fallback secret for andy-docs-api.</summary>
    public const string AndyDocsApiClientId = "andy-docs-api";
    public const string AndyDocsApiClientSecret = "andy-docs-api-secret-change-in-production";
    public const string AndyDocsApiScope = "urn:andy-docs-api";

    /// <summary>Token-exchange actor client seeded from the fixture manifest.</summary>
    public const string AndyContainersApiClientId = "andy-containers-api";
    public const string AndyModelsApiAudience = "urn:andy-models-api";

    private readonly Dictionary<string, string?> _priorEnvValues = new();
    private readonly string _dbPath;

    public CustomWebApplicationFactory()
    {
        _dbPath = Path.Combine(
            Path.GetTempPath(),
            $"andy-auth-tests-{Guid.NewGuid():N}.sqlite");

        // Isolated SQLite instead of the Development PostgreSQL. The app's
        // provider selection (DatabaseProviderExtensions) reads these keys;
        // Program.cs bootstraps the SQLite schema with EnsureCreated.
        SetEnv("ASPNETCORE_ENVIRONMENT", "Development");
        SetEnv("Database__Provider", "Sqlite");
        SetEnv("ConnectionStrings__Sqlite", $"Data Source={_dbPath}");

        // Supply the OAuth clients the tests need. These are manifest-driven
        // and normally live in sibling repos (absent in CI); the fixture
        // manifests under Fixtures/ stand in for them (andy-docs-api,
        // andy-containers-api, and the urn:andy-models-api audience).
        SetEnv("Registrations__ManifestPaths__0", FixturesManifestDirectory);

        // Token-exchange policy so the seeder grants andy-containers-api the
        // rsr:urn:andy-models-api resource permission (RFC 8693 OBO target).
        // Exercised by TokenExchangeIntegrationTests.
        SetEnv("TokenExchange__Policies__0__ActorClientId", AndyContainersApiClientId);
        SetEnv("TokenExchange__Policies__0__Audience", AndyModelsApiAudience);

        // Give the seeded admin user a deterministic password so admin-gated
        // flows can be exercised for real (otherwise DbSeeder generates a
        // random one). test@andy.local already gets the fixed Test123!.
        SetEnv("ADMIN_PASSWORD_DEFAULT", AdminPassword);

        // Keep test output bounded — the host would otherwise emit hundreds of
        // Debug lines per request (Development default is Debug).
        SetEnv("Logging__LogLevel__Default", "Warning");
    }

    /// <summary>
    /// Absolute path to the copied-to-output Fixtures directory holding the
    /// registration manifest(s). Resolved from the test assembly location so
    /// it works regardless of the working directory the runner uses.
    /// </summary>
    public static string FixturesManifestDirectory =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (disposing)
        {
            foreach (var (key, value) in _priorEnvValues)
            {
                Environment.SetEnvironmentVariable(key, value);
            }

            TryDeleteSqliteFile();
        }
    }

    private void TryDeleteSqliteFile()
    {
        foreach (var path in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm", _dbPath + "-journal" })
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // Best-effort cleanup; the temp file will be reaped by the OS.
            }
        }
    }

    private void SetEnv(string key, string? value)
    {
        _priorEnvValues[key] = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, value);
    }
}
