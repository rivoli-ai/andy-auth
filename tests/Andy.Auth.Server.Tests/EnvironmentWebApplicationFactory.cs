using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Andy.Auth.Server.Tests;

// Shared `WebApplicationFactory<Program>` for env-driven integration
// tests. Program.cs reads `builder.Configuration` before
// WebApplicationFactory's `ConfigureAppConfiguration` callbacks run,
// so config has to be set via environment variables — ASP.NET Core's
// EnvironmentVariablesConfigurationProvider maps `Key__SubKey=Value`
// to `Key:SubKey=Value` in config and is visible from the very first
// configuration read.
//
// Tests in this assembly run serially (xunit.runner.json sets
// parallelizeTestCollections=false and parallelizeAssembly=false),
// so the shared environment-variable mutation is safe between tests.
//
// Constructor parameters:
//   environmentName   ASPNETCORE_ENVIRONMENT (Development / Docker /
//                     Embedded / Production / Staging / UAT).
//   dbPath            SQLite path so DbSeeder doesn't require Postgres.
//   issuer            OpenIddict:Issuer URL. Production's appsettings
//                     ships a `SET_VIA_ENVIRONMENT_VARIABLE` placeholder
//                     that crashes `new Uri(…)` unless overridden here.
//   keysPath          Nullable. Used by Embedded mode and by
//                     Production with persisted keys.
//   useEphemeralKeys  Only meaningful for Production. Ignored elsewhere.
internal sealed class EnvironmentWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly Dictionary<string, string?> _priorEnvValues = new();
    private readonly string _environmentName;

    public EnvironmentWebApplicationFactory(
        string environmentName,
        string dbPath,
        string issuer,
        string? keysPath = null,
        bool useEphemeralKeys = false)
    {
        _environmentName = environmentName;
        SetEnv("ASPNETCORE_ENVIRONMENT", environmentName);
        SetEnv("OpenIddict__Issuer", issuer);
        SetEnv("Database__Provider", "Sqlite");
        SetEnv("ConnectionStrings__Sqlite", $"Data Source={dbPath}");
        SetEnv("ConnectionStrings__DefaultConnection", $"Data Source={dbPath}");
        SetEnv("OpenIddict__SigningKeys__Path", keysPath);
        SetEnv("OpenIddict__UseEphemeralKeys", useEphemeralKeys ? "true" : "false");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(_environmentName);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var (key, value) in _priorEnvValues)
            {
                Environment.SetEnvironmentVariable(key, value);
            }
        }
        base.Dispose(disposing);
    }

    private void SetEnv(string key, string? value)
    {
        _priorEnvValues[key] = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, value);
    }
}
