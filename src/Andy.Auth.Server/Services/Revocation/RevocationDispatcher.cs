using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Andy.Auth.Server.Services.Revocation;

public sealed class RevocationDispatcher(ApplicationDbContext db, IOptions<RevocationDeliveryOptions> delivery,
    IOptionsMonitor<OpenIddictServerOptions> server, IHttpClientFactory clients, TimeProvider clock,
    ILogger<RevocationDispatcher> logger)
{
    public const string HttpClientName = "Andy.Auth.RevocationDelivery";
    public const string EventType = "urn:rivoli:params:secevent:session-revoked";

    public async Task<int> DispatchAsync(CancellationToken cancellationToken = default)
    {
        if (!delivery.Value.Enabled) return 0;
        var now = clock.GetUtcNow().UtcDateTime;
        var recipients = delivery.Value.Targets.Select(target => target.Audience).ToArray();
        var candidates = await db.RevocationOutbox.AsNoTracking()
            .Where(message => recipients.Contains(message.Recipient) && message.NextAttemptAtUtc <= now && (message.LeaseUntilUtc == null || message.LeaseUntilUtc < now))
            .OrderBy(message => message.CreatedAtUtc).ThenBy(message => message.Id).Take(32).ToListAsync(cancellationToken);
        var sent = 0;
        foreach (var message in candidates)
        {
            var recipient = delivery.Value.Targets.SingleOrDefault(target => target.Audience == message.Recipient);
            if (recipient == null) continue; // retain until the operator restores the recipient configuration
            var lease = Guid.NewGuid().ToString("N");
            var leasedUntil = clock.GetUtcNow().UtcDateTime.AddSeconds(30);
            if (await db.RevocationOutbox.Where(row => row.Id == message.Id && row.NextAttemptAtUtc <= now &&
                    (row.LeaseUntilUtc == null || row.LeaseUntilUtc < now))
                .ExecuteUpdateAsync(set => set.SetProperty(row => row.LeaseToken, lease)
                    .SetProperty(row => row.LeaseUntilUtc, leasedUntil), cancellationToken) != 1) continue;
            string? error = null;
            var permanent = false;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, recipient.Endpoint)
                {
                    Content = new StringContent(CreateToken(message), Encoding.ASCII, "application/secevent+jwt")
                };
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                using var response = await clients.CreateClient(HttpClientName).SendAsync(request, cancellationToken);
                if (response.StatusCode == HttpStatusCode.Accepted &&
                    (await response.Content.ReadAsByteArrayAsync(cancellationToken)).Length == 0)
                {
                    await db.RevocationOutbox.Where(row => row.Id == message.Id && row.LeaseToken == lease)
                        .ExecuteDeleteAsync(cancellationToken);
                    sent++;
                    continue;
                }
                error = "http_" + (int)response.StatusCode;
                permanent = (int)response.StatusCode < 500 && response.StatusCode is not
                    (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or InvalidOperationException)
            {
                if (cancellationToken.IsCancellationRequested) throw;
                error = exception is InvalidOperationException ? "signing_unavailable" : "transport_unavailable";
            }
            var attempts = Math.Min(message.Attempts + 1, 30);
            var next = permanent ? DateTime.MaxValue : clock.GetUtcNow().UtcDateTime.AddSeconds(Math.Min(300, 5 * Math.Pow(2, attempts - 1)));
            await db.RevocationOutbox.Where(row => row.Id == message.Id && row.LeaseToken == lease)
                .ExecuteUpdateAsync(set => set.SetProperty(row => row.Attempts, attempts)
                    .SetProperty(row => row.LastError, error).SetProperty(row => row.NextAttemptAtUtc, next)
                    .SetProperty(row => row.LeaseToken, (string?)null).SetProperty(row => row.LeaseUntilUtc, (DateTime?)null), cancellationToken);
            logger.LogWarning("Revocation delivery {MessageId} to {Recipient} failed: {Error}; requires operator repair: {Permanent}",
                message.Id, message.Recipient, error, permanent);
        }
        return sent;
    }

    private string CreateToken(RevocationOutboxMessage message)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var options = server.CurrentValue;
        var credential = options.SigningCredentials
            .Where(item => item.Algorithm == SecurityAlgorithms.RsaSha256 &&
                (item.Key is RsaSecurityKey || item.Key is X509SecurityKey))
            .Where(item => item.Key is not X509SecurityKey certificate ||
                certificate.Certificate.NotBefore.ToUniversalTime() <= now && certificate.Certificate.NotAfter.ToUniversalTime() > now)
            .OrderByDescending(item => item.Key is X509SecurityKey)
            .ThenByDescending(item => item.Key is X509SecurityKey certificate ? certificate.Certificate.NotAfter : DateTime.MinValue)
            .FirstOrDefault() ?? throw new InvalidOperationException("No active RSA signing credential is available for security events.");
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "secevent+jwt", Issuer = options.Issuer?.AbsoluteUri ??
                throw new InvalidOperationException("A canonical issuer is required for security events."),
            Audience = message.Recipient, IssuedAt = now, SigningCredentials = credential,
            Claims = new Dictionary<string, object>
            {
                ["jti"] = message.Id,
                ["events"] = new Dictionary<string, object>
                {
                    [EventType] = new Dictionary<string, object>
                    {
                        ["sid"] = message.SessionId,
                        ["occurred_at"] = new DateTimeOffset(DateTime.SpecifyKind(message.CreatedAtUtc, DateTimeKind.Utc)).ToUnixTimeSeconds()
                    }
                }
            }
        });
    }
}

public sealed class RevocationDeliveryWorker(IServiceScopeFactory scopes, StartupReadinessState readiness,
    TimeProvider clock, ILogger<RevocationDeliveryWorker> logger) : BackgroundService
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
                    await scope.ServiceProvider.GetRequiredService<RevocationDispatcher>().DispatchAsync(stoppingToken);
                }
                await Task.Delay(TimeSpan.FromSeconds(1), clock, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                logger.LogError(exception, "Revocation delivery unavailable; pending events remain durable");
                await Task.Delay(TimeSpan.FromSeconds(5), clock, stoppingToken);
            }
        }
    }
}
