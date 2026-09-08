using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;

namespace Andy.Auth.Dpop;

public sealed class RedisDpopReplayStore(IConnectionMultiplexer connection) : IDpopReplayStore
{
    public async Task<bool> TryUseAsync(string thumbprint, string id, TimeSpan retention, CancellationToken cancellationToken)
    {
        var key = "andy:dpop:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(thumbprint + "\n" + id)));
        return await connection.GetDatabase().StringSetAsync(key, "1", retention, When.NotExists).WaitAsync(cancellationToken);
    }
}

public static class DpopReplayRegistration
{
    public static IServiceCollection AddRedisDpopReplayProtection(this IServiceCollection services, string connectionString)
    {
        var options = ConfigurationOptions.Parse(connectionString);
        options.AbortOnConnectFail = false;
        services.TryAddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(options));
        services.TryAddSingleton<IDpopReplayStore, RedisDpopReplayStore>();
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<DpopProofValidator>();
        return services;
    }
}
