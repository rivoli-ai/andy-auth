using System.Security.Cryptography;
using System.Text.Json;
using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Lib.Net.Http.WebPush;
using Lib.Net.Http.WebPush.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace Andy.Auth.Server.Services.Ciba;

public sealed record CibaSubscription(string Endpoint, string P256dh, string Auth);

public sealed class CibaPushDelivery(ApplicationDbContext db, IOptions<CibaOptions> settings,
    IOptionsMonitor<OpenIddictServerOptions> server, IDataProtectionProvider protection,
    IHttpClientFactory clients, TimeProvider clock, ILogger<CibaPushDelivery> logger)
{
    public const string HttpClientName = "Andy.Auth.CibaPush";
    public const string ProtectionPurpose = "Andy.Auth.Ciba.PushSubscription.v1";

    public async Task<int> DispatchAsync(CancellationToken cancellationToken = default)
    {
        if (!settings.Value.Enabled) return 0;
        var now = clock.GetUtcNow().UtcDateTime;
        var candidates = await db.CibaAuthentications.AsNoTracking().Where(row => row.Status == "pending" &&
            !row.PushDelivered && row.ExpiresAtUtc > now && row.NextPushAtUtc <= now &&
            (row.PushLeaseUntilUtc == null || row.PushLeaseUntilUtc < now)).OrderBy(row => row.CreatedAtUtc)
            .Take(16).ToListAsync(cancellationToken);
        var delivered = 0;
        foreach (var row in candidates)
        {
            var lease = Guid.NewGuid().ToString("N");
            if (await db.CibaAuthentications.Where(item => item.Id == row.Id && item.Status == "pending" &&
                !item.PushDelivered && (item.PushLeaseUntilUtc == null || item.PushLeaseUntilUtc < now))
                .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.PushLease, lease)
                    .SetProperty(item => item.PushLeaseUntilUtc, now.AddSeconds(30)), cancellationToken) != 1) continue;
            try
            {
                var device = await db.CibaPushDevices.AsNoTracking().SingleOrDefaultAsync(item => item.UserId == row.UserId, cancellationToken);
                if (device == null) throw new InvalidOperationException("No enrolled device");
                var subscription = JsonSerializer.Deserialize<CibaSubscription>(protection.CreateProtector(ProtectionPurpose).Unprotect(device.ProtectedSubscription))!;
                if (!settings.Value.AllowsEndpoint(subscription.Endpoint)) throw new InvalidOperationException("Push origin no longer allowed");
                var issuer = server.CurrentValue.Issuer ?? throw new InvalidOperationException("CIBA requires an explicit issuer");
                var approvalUri = new Uri(new Uri(issuer.AbsoluteUri.TrimEnd('/') + "/"), "Ciba/Approve/" + row.Id);
                var payload = JsonSerializer.Serialize(new { title = "Sign-in approval", body = row.BindingMessage,
                    url = approvalUri.AbsoluteUri, tag = row.Id });
                using var auth = new VapidAuthentication(settings.Value.VapidPublicKey, settings.Value.VapidPrivateKey)
                { Subject = settings.Value.VapidSubject };
                var push = new PushServiceClient(clients.CreateClient(HttpClientName)) { AutoRetryAfter = false };
                await push.RequestPushMessageDeliveryAsync(new PushSubscription
                {
                    Endpoint = subscription.Endpoint,
                    Keys = new Dictionary<string, string> { ["p256dh"] = subscription.P256dh, ["auth"] = subscription.Auth }
                }, new PushMessage(payload) { TimeToLive = Math.Max(1, (int)(row.ExpiresAtUtc - clock.GetUtcNow().UtcDateTime).TotalSeconds) }, auth, cancellationToken);
                delivered += await db.CibaAuthentications.Where(item => item.Id == row.Id && item.PushLease == lease)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.PushDelivered, true)
                        .SetProperty(item => item.PushLease, (string?)null).SetProperty(item => item.PushLeaseUntilUtc, (DateTime?)null), cancellationToken);
            }
            catch (Exception error)
            {
                // Do not log capability URLs, keys, hints, or encrypted push payloads.
                logger.LogWarning("CIBA notification attempt failed ({FailureType}, HTTP {StatusCode})",
                    error.GetType().Name, error is PushServiceClientException pushError ? (int)pushError.StatusCode : 0);
                await db.CibaAuthentications.Where(item => item.Id == row.Id && item.PushLease == lease)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.PushAttempts, item => item.PushAttempts + 1)
                        .SetProperty(item => item.NextPushAtUtc, clock.GetUtcNow().UtcDateTime.AddSeconds(Math.Min(30, 5 * (row.PushAttempts + 1))))
                        .SetProperty(item => item.PushLease, (string?)null).SetProperty(item => item.PushLeaseUntilUtc, (DateTime?)null), cancellationToken);
            }
        }
        await db.CibaAuthentications.Where(row => row.ExpiresAtUtc < now.AddDays(-1)).ExecuteDeleteAsync(cancellationToken);
        return delivered;
    }
}

public sealed class CibaPushWorker(IServiceScopeFactory scopes, StartupReadinessState readiness,
    ILogger<CibaPushWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (readiness.IsReady)
                {
                    using var scope = scopes.CreateScope();
                    await scope.ServiceProvider.GetRequiredService<CibaPushDelivery>().DispatchAsync(stoppingToken);
                }
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error)
            {
                logger.LogError("CIBA notification worker unavailable ({FailureType})", error.GetType().Name);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }
}
