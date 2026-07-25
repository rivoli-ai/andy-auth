using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Readiness health check (issue #130). Reports <see cref="HealthStatus.Healthy"/>
/// only once startup migrations and required seeding have both completed, and
/// <see cref="HealthStatus.Unhealthy"/> otherwise (DB unavailable, migration
/// failure, or a required seed failure such as missing production admin/client
/// secrets). Tagged <c>"ready"</c> and mapped at <c>/ready</c>; container and
/// Railway probes use it for traffic admission.
/// </summary>
public sealed class StartupReadinessHealthCheck : IHealthCheck
{
    private readonly StartupReadinessState _state;

    public StartupReadinessHealthCheck(StartupReadinessState state) => _state = state;

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var data = new Dictionary<string, object>
        {
            ["migrationsApplied"] = _state.MigrationsApplied,
            ["seedCompleted"] = _state.SeedCompleted,
        };

        if (_state.IsReady)
        {
            return Task.FromResult(
                HealthCheckResult.Healthy("Startup migration and seeding complete.", data));
        }

        var reason = _state.FailureReason
            ?? "Startup migration/seeding has not completed yet.";
        return Task.FromResult(HealthCheckResult.Unhealthy(reason, data: data));
    }
}
