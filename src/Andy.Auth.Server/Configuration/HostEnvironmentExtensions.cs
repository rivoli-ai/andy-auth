using Microsoft.Extensions.Hosting;

namespace Andy.Auth.Server.Configuration;

// Named accessors for the three deployment modes andy-auth supports.
// The canonical description of the contract — modes, port ranges,
// trust model — lives in `andy-service-template/docs/ports.md`. This
// file is the andy-auth copy of the runtime predicates only.
//
// - Development (ASPNETCORE_ENVIRONMENT=Development): `dotnet run` on
//   the host. Liberal defaults — Swagger, developer exception pages,
//   SSL validation bypass, RBAC bypass — intended for a developer
//   iterating on the service directly in their shell. Ephemeral keys.
//
// - Docker     (ASPNETCORE_ENVIRONMENT=Docker): docker-compose stack.
//   Ports offset +2000 from Development so both can coexist on one
//   machine. Config is env-var driven (no static appsettings.Docker.json
//   today; compose env vars supply everything Program.cs reads).
//   Local-development trust model — ephemeral keys, transport security
//   off — same as Development. Note: docker-compose.yml currently sets
//   ENV=Development; ENV=Docker is wired up and works (closes #75) but
//   not yet adopted by the compose file.
//
// - Embedded   (ASPNETCORE_ENVIRONMENT=Embedded): bundled inside the
//   Conductor desktop app behind a unified proxy on port 9100. All
//   configuration is injected by Conductor at process start — no
//   static appsettings file for this environment. This mode must be
//   production-like: no developer exception pages, no Swagger, real
//   RBAC enforcement, persisted signing keys.
public static class HostEnvironmentExtensions
{
    public const string EmbeddedEnvironmentName = "Embedded";
    public const string DockerEnvironmentName = "Docker";

    /// <summary>
    /// True when ASPNETCORE_ENVIRONMENT == "Embedded" — the service
    /// is running inside Conductor's bundled service host.
    /// </summary>
    public static bool IsEmbedded(this IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        return environment.IsEnvironment(EmbeddedEnvironmentName);
    }

    /// <summary>
    /// True when ASPNETCORE_ENVIRONMENT == "Docker" — the service is
    /// running inside a docker-compose stack.
    /// </summary>
    public static bool IsDocker(this IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        return environment.IsEnvironment(DockerEnvironmentName);
    }

    /// <summary>
    /// True when the service is running in any non-production mode
    /// (Development, Docker, or Embedded). Use for behaviors that
    /// are safe across all local-development deployment shapes —
    /// e.g. disabling HTTPS metadata requirement for the OIDC
    /// discovery document when talking to andy-auth over plain HTTP
    /// through a local proxy.
    ///
    /// Do NOT use for behaviors that leak sensitive information
    /// (Swagger UI, developer exception pages, permission bypass) —
    /// those must stay gated off <see cref="IHostEnvironment.IsDevelopment"/>
    /// so the shipping Conductor app does not expose them.
    /// </summary>
    public static bool IsLocalOrEmbedded(this IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        return !environment.IsProduction();
    }
}
