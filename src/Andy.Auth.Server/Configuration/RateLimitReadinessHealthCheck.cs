using Microsoft.Extensions.Diagnostics.HealthChecks;
using StackExchange.Redis;

namespace Andy.Auth.Server.Configuration;

public sealed class RateLimitReadinessHealthCheck(IServiceProvider services) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var redis = services.GetService<IConnectionMultiplexer>();
        if (redis == null) return HealthCheckResult.Healthy();
        try
        {
            await redis.GetDatabase().PingAsync().WaitAsync(TimeSpan.FromSeconds(2), cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (Exception exception) when (exception is RedisException or TimeoutException or OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Shared rate-limit store unavailable.");
        }
    }
}
