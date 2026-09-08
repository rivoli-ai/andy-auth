using AspNetCoreRateLimit;
using AspNetCoreRateLimit.Redis;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;

namespace Andy.Auth.Server.Configuration;

public static class DistributedRateLimiting
{
    public static void AddAuthRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var connection = configuration["RateLimiting:RedisConnectionString"];
        var required = configuration.GetValue<bool>("RateLimiting:RequireDistributed");
        if (required && string.IsNullOrWhiteSpace(connection))
            throw new InvalidOperationException("Distributed rate limiting requires RateLimiting:RedisConnectionString.");

        // Policies are immutable local configuration. Only the request counters need
        // distributed state; the Redis strategy performs its increment and TTL atomically.
        services.AddInMemoryRateLimiting();
        if (!string.IsNullOrWhiteSpace(connection))
        {
            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(connection);
                options.AbortOnConnectFail = false;
                return ConnectionMultiplexer.Connect(options);
            });
            services.Replace(ServiceDescriptor.Singleton<IProcessingStrategy, RedisProcessingStrategy>());
        }
    }
}
