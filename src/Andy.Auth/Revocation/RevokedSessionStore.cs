using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Revocation;

/// <summary>A shared durable denial store. Duplicate writes must be idempotent.</summary>
public interface IRevokedSessionStore
{
    Task RevokeAsync(string issuer, string sessionId, CancellationToken cancellationToken);
    Task<bool> IsRevokedAsync(string issuer, string sessionId, CancellationToken cancellationToken);
}

public sealed class DistributedRevokedSessionStore : IRevokedSessionStore
{
    private readonly IDistributedCache cache;
    private readonly TimeSpan retention;

    public DistributedRevokedSessionStore(IDistributedCache cache, IHostEnvironment environment,
        IOptions<RevocationReceiverOptions> options)
    {
        if (cache is MemoryDistributedCache && !environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
            throw new InvalidOperationException("Revocation receipt requires shared durable storage outside Development/Testing.");
        this.cache = cache;
        retention = options.Value.Retention;
    }

    private static string Key(string issuer, string sessionId) => "andy:revoked:" +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(issuer.TrimEnd('/') + "/\n" + sessionId)));

    public Task RevokeAsync(string issuer, string sessionId, CancellationToken cancellationToken) =>
        cache.SetAsync(Key(issuer, sessionId), new byte[] { 1 },
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = retention }, cancellationToken);

    public async Task<bool> IsRevokedAsync(string issuer, string sessionId, CancellationToken cancellationToken) =>
        await cache.GetAsync(Key(issuer, sessionId), cancellationToken) != null;
}

public sealed class RequireRevocationStoreStartup(IRevokedSessionStore store) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) { _ = store; return Task.CompletedTask; }
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
