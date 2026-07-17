using System.Net;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Pins andy-auth#130: startup must not report the service ready when migration
// or required seeding failed. /health stays a dependency-free liveness probe;
// /ready is a distinct readiness probe gated on the migration/seed init state.
public class ReadinessCheckTests : IDisposable
{
    private readonly string _baseTemp;

    public ReadinessCheckTests()
    {
        _baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-ready-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_baseTemp);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_baseTemp))
            {
                Directory.Delete(_baseTemp, recursive: true);
            }
        }
        catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Ready_WhenMigrationAndSeedSucceed_Returns200()
    {
        // Embedded + SQLite: schema is EnsureCreated'd and seeding completes
        // (Embedded allows generated admin passwords), so readiness is healthy.
        using var factory = CreateFactory(
            HostEnvironmentExtensions.EmbeddedEnvironmentName,
            keysPath: NewDir("keys"));
        using var client = HttpClient(factory);

        var ready = await client.GetAsync("/ready");
        ready.StatusCode.Should().Be(HttpStatusCode.OK,
            "migration + seeding succeeded, so the service is ready");

        var health = await client.GetAsync("/health");
        health.StatusCode.Should().Be(HttpStatusCode.OK, "liveness is always healthy once the process is up");
    }

    [Fact]
    public async Task Ready_WhenDatabaseUnavailable_Returns503_ButHealthStays200()
    {
        // Point at a PostgreSQL host that refuses connections: MigrateAsync
        // throws, the startup block records the failure, the process stays up.
        using var factory = CreateFactory("Development", extra: new[]
        {
            new KeyValuePair<string, string?>("Database__Provider", "PostgreSql"),
            new KeyValuePair<string, string?>("ConnectionStrings__DefaultConnection",
                "Host=127.0.0.1;Port=59999;Database=andy_auth;Username=x;Password=x;Timeout=2;Command Timeout=2"),
        });
        // Development applies UseHttpsRedirection; use an https base so the probe
        // requests reach the endpoints instead of getting a 307.
        using var client = HttpsOrHttpClient(factory, https: true);

        var ready = await client.GetAsync("/ready");
        ready.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable,
            "an unavailable database means migration failed, so the service is not ready (#130)");

        var health = await client.GetAsync("/health");
        health.StatusCode.Should().Be(HttpStatusCode.OK,
            "liveness must stay green even when the DB is down — the process itself is healthy");
    }

    [Fact]
    public async Task Ready_WhenProductionRequiredSeedFails_Returns503_ButHealthStays200()
    {
        // Production + SQLite: the schema is created (migration ok) but the
        // seeder fails a required step (no admin/client secrets configured
        // outside Development/Embedded), so readiness is unhealthy while
        // liveness stays healthy.
        using var factory = CreateFactory("Production",
            keysPath: NewDir("keys"),
            extra: new[]
            {
                // Ensure no ambient admin passwords satisfy the seeder.
                new KeyValuePair<string, string?>("ADMIN_PASSWORD_SAM", null),
                new KeyValuePair<string, string?>("ADMIN_PASSWORD_TY", null),
                new KeyValuePair<string, string?>("ADMIN_PASSWORD_DEFAULT", null),
            },
            issuer: "https://auth.example.test/");
        using var client = HttpsOrHttpClient(factory, https: true);

        var ready = await client.GetAsync("/ready");
        ready.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable,
            "a required seed failure (missing production secrets) means the service is not ready (#130)");

        var health = await client.GetAsync("/health");
        health.StatusCode.Should().Be(HttpStatusCode.OK,
            "liveness must stay green even when seeding failed");
    }

    [Fact]
    public async Task Ready_WhenAdminSeedPasswordIsMalformed_Returns503_ButHealthStays200()
    {
        // Migration succeeds (SQLite), but a supplied admin password that violates
        // the Identity policy makes UserManager.CreateAsync fail. That is a required
        // seed failure: it must throw (not just warn) so readiness stays unhealthy
        // and no admin-less deployment is admitted (#130).
        using var factory = CreateFactory("Development", extra: new[]
        {
            new KeyValuePair<string, string?>("ADMIN_PASSWORD_SAM", "weak"), // too short, no upper/digit
        });
        // Development applies UseHttpsRedirection; use https so probes reach the endpoints.
        using var client = HttpsOrHttpClient(factory, https: true);

        var ready = await client.GetAsync("/ready");
        ready.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable,
            "a rejected admin password is a required-seed failure, so the service is not ready (#130)");

        var health = await client.GetAsync("/health");
        health.StatusCode.Should().Be(HttpStatusCode.OK,
            "liveness must stay green even when a required seed step failed");
    }

    private string NewDir(string name)
    {
        var dir = Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"), name);
        Directory.CreateDirectory(dir);
        return dir;
    }

    private EnvironmentWebApplicationFactory CreateFactory(
        string environmentName,
        string? keysPath = null,
        string? issuer = null,
        IEnumerable<KeyValuePair<string, string?>>? extra = null)
    {
        var modeDir = Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(modeDir);

        return new EnvironmentWebApplicationFactory(
            environmentName: environmentName,
            dbPath: Path.Combine(modeDir, "andy-auth.sqlite"),
            issuer: issuer ?? "http://localhost:9100/auth/",
            keysPath: keysPath,
            extraEnvironment: extra);
    }

    private static HttpClient HttpClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("http://localhost/")
        });

    private static HttpClient HttpsOrHttpClient(WebApplicationFactory<Program> factory, bool https) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(https ? "https://localhost/" : "http://localhost/")
        });
}
