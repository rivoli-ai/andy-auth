namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Singleton that records the outcome of the startup migration + seeding step so
/// the readiness probe (<c>/ready</c>) can gate traffic admission on it (issue
/// #130). The liveness probe (<c>/health</c>) is intentionally independent of
/// this state: a process that booted but failed to migrate/seed is alive (should
/// not be killed) yet not ready (must not receive traffic).
/// </summary>
public sealed class StartupReadinessState
{
    private volatile bool _migrationsApplied;
    private volatile bool _seedCompleted;

    /// <summary>True once the database schema has been created/migrated.</summary>
    public bool MigrationsApplied => _migrationsApplied;

    /// <summary>True once all required seed data has been written.</summary>
    public bool SeedCompleted => _seedCompleted;

    /// <summary>The last recorded init failure message, if any.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>The service is ready only when both migration and seeding have completed.</summary>
    public bool IsReady => _migrationsApplied && _seedCompleted;

    public void MarkMigrationsApplied() => _migrationsApplied = true;

    public void MarkSeedCompleted() => _seedCompleted = true;

    public void MarkFailed(string reason) => FailureReason = reason;
}
