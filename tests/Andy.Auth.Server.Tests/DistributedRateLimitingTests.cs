using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Middleware;
using AspNetCoreRateLimit;
using AspNetCoreRateLimit.Redis;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using StackExchange.Redis;

namespace Andy.Auth.Server.Tests;

public sealed class DistributedRateLimitingTests
{
    [Fact]
    public void RequiredDistributedStoreCannotSilentlyUseMemory()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["RateLimiting:RequireDistributed"] = "true" }).Build();
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddAuthRateLimiting(configuration));
    }

    [Fact]
    public void RedisConfigurationSelectsAtomicStrategy()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["RateLimiting:RedisConnectionString"] = "localhost" }).Build();
        var services = new ServiceCollection();
        services.AddAuthRateLimiting(configuration);
        Assert.Equal(typeof(RedisProcessingStrategy), services.Single(s => s.ServiceType == typeof(IProcessingStrategy)).ImplementationType);
    }

    [Fact]
    public async Task CounterFailureRejectsRequestWithoutLocalFallback()
    {
        var context = new DefaultHttpContext();
        var middleware = new RateLimitAvailabilityMiddleware(_ => throw new RedisConnectionException(ConnectionFailureType.UnableToConnect, "unavailable"),
            NullLogger<RateLimitAvailabilityMiddleware>.Instance);
        await middleware.InvokeAsync(context);
        Assert.Equal(503, context.Response.StatusCode);
        Assert.Equal("no-store", context.Response.Headers.CacheControl);
        Assert.Equal("5", context.Response.Headers.RetryAfter);
    }

    [Fact]
    public async Task UnavailableRedisMakesReadinessUnhealthy()
    {
        var database = new Mock<IDatabase>();
        database.Setup(d => d.PingAsync(It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "unavailable"));
        var connection = new Mock<IConnectionMultiplexer>();
        connection.Setup(c => c.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(database.Object);
        using var services = new ServiceCollection().AddSingleton(connection.Object).BuildServiceProvider();
        var result = await new RateLimitReadinessHealthCheck(services).CheckHealthAsync(new());
        Assert.Equal(Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy, result.Status);
    }

    [RedisFact]
    public async Task IndependentReplicasAndRestartShareOneAtomicAllowance()
    {
        var connection = Environment.GetEnvironmentVariable("ANDY_TEST_REDIS")!;
        using var first = await ConnectionMultiplexer.ConnectAsync(connection);
        using var second = await ConnectionMultiplexer.ConnectAsync(connection);
        var config = Mock.Of<IRateLimitConfiguration>();
        RedisProcessingStrategy Strategy(IConnectionMultiplexer redis) => new(redis, config, NullLogger<RedisProcessingStrategy>.Instance);
        var key = "andy-auth-test:" + Guid.NewGuid().ToString("N");
        try
        {
            var replicas = new[] { Strategy(first), Strategy(second) };
            var results = await Task.WhenAll(Enumerable.Range(0, 100).Select(i => replicas[i % 2].IncrementAsync(key, TimeSpan.FromMinutes(1))));
            Assert.Equal(Enumerable.Range(1, 100).Select(i => (double)i), results.Select(r => r.Count).OrderBy(c => c));
            Assert.Equal(10, results.Count(r => r.Count <= 10));
            using var restarted = await ConnectionMultiplexer.ConnectAsync(connection);
            Assert.Equal(101, (await Strategy(restarted).IncrementAsync(key, TimeSpan.FromMinutes(1))).Count);
            var ttl = await first.GetDatabase().KeyTimeToLiveAsync(key);
            Assert.NotNull(ttl);
            Assert.InRange(ttl.Value.TotalSeconds, 1, 60);
        }
        finally { await first.GetDatabase().KeyDeleteAsync(key); }
    }
}

public sealed class RedisFactAttribute : FactAttribute
{
    public RedisFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ANDY_TEST_REDIS")))
            Skip = "Set ANDY_TEST_REDIS to run the real shared-counter test (required in CI).";
    }
}
