using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using StackExchange.Redis;

namespace Andy.Auth.Server.Services.Ciba;

public sealed record CibaPollResult(ClaimsPrincipal? Principal, string? Error);

public sealed class CibaService(ApplicationDbContext db, IOptions<CibaOptions> options, TimeProvider clock,
    IConnectionMultiplexer redis, UserManager<ApplicationUser> users, SignInManager<ApplicationUser> signIn,
    SessionService sessions, TokenClaimsPrincipalFactory principals, IOpenIddictApplicationManager applications)
{
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public async Task<string?> StartAsync(string userId, string clientId, string scope, string binding, int? requestedExpiry,
        CancellationToken cancellationToken)
    {
        if (!await redis.GetDatabase().StringSetAsync("andy:ciba:prompt:" + Hash(userId), "1", TimeSpan.FromSeconds(30), When.NotExists)
            .WaitAsync(cancellationToken)) return null;
        var now = clock.GetUtcNow().UtcDateTime;
        var opaque = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var interval = (int)options.Value.PollingInterval.TotalSeconds;
        db.CibaAuthentications.Add(new CibaAuthentication
        {
            RequestHash = Hash(opaque), ClientId = clientId, UserId = userId, Scope = scope, BindingMessage = binding,
            CreatedAtUtc = now, ExpiresAtUtc = now.AddSeconds(Math.Min(requestedExpiry ?? int.MaxValue, options.Value.AuthenticationLifetime.TotalSeconds)),
            NextPollAtUtc = now.AddSeconds(interval), PollIntervalSeconds = interval, NextPushAtUtc = now
        });
        await db.SaveChangesAsync(cancellationToken);
        return opaque;
    }

    public async Task<CibaPollResult> PollAsync(string clientId, string? opaque, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(opaque) || opaque.Length > 128) return new(null, "invalid_grant");
        var hash = Hash(opaque);
        var row = await db.CibaAuthentications.AsNoTracking().SingleOrDefaultAsync(item => item.RequestHash == hash && item.ClientId == clientId, cancellationToken);
        if (row == null || row.Status == "consumed") return new(null, "invalid_grant");
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
        if (application == null || await applications.HasClientTypeAsync(application, OpenIddictConstants.ClientTypes.Public, cancellationToken))
            return new(null, "unauthorized_client");
        var properties = await applications.GetPropertiesAsync(application, cancellationToken);
        if (!properties.TryGetValue(CibaOptions.DeliveryModeProperty, out var mode) || mode.GetString() != "poll")
            return new(null, "unauthorized_client");
        foreach (var scope in row.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            if (scope is not ("openid" or "offline_access") &&
                !await applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.Prefixes.Scope + scope, cancellationToken))
                return new(null, "invalid_scope");
        var now = clock.GetUtcNow().UtcDateTime;
        if (row.ExpiresAtUtc <= now) return new(null, "expired_token");
        if (row.Status == "denied") return new(null, "access_denied");
        if (row.NextPollAtUtc > now)
        {
            if (row.PollIntervalSeconds >= 60)
            {
                await db.CibaAuthentications.Where(item => item.Id == row.Id && item.Status != "consumed")
                    .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Status, "denied"), cancellationToken);
                return new(null, "invalid_request");
            }
            await db.CibaAuthentications.Where(item => item.Id == row.Id && item.NextPollAtUtc == row.NextPollAtUtc && item.Status != "consumed")
                .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.PollIntervalSeconds, Math.Min(60, row.PollIntervalSeconds + 5))
                    .SetProperty(item => item.NextPollAtUtc, now.AddSeconds(Math.Min(60, row.PollIntervalSeconds + 5))), cancellationToken);
            return new(null, "slow_down");
        }
        if (await db.CibaAuthentications.Where(item => item.Id == row.Id && item.NextPollAtUtc == row.NextPollAtUtc && item.Status == row.Status)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.NextPollAtUtc, now.AddSeconds(row.PollIntervalSeconds)), cancellationToken) != 1)
            return new(null, "slow_down");
        if (row.Status == "pending") return new(null, "authorization_pending");
        var user = await users.FindByIdAsync(row.UserId);
        if (user == null || row.SecurityStampHash != Hash(await users.GetSecurityStampAsync(user)) || user.DeletedAt != null || !await signIn.CanSignInAsync(user) || await users.IsLockedOutAsync(user) ||
            !await sessions.IsSessionValidForUserAsync(row.SessionId, row.UserId)) return new(null, "access_denied");
        if (await db.CibaAuthentications.Where(item => item.Id == row.Id && item.Status == "approved" && item.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Status, "consumed"), cancellationToken) != 1)
            return new(null, "invalid_grant");
        var principal = await principals.CreateAsync(user, row.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries), clientId);
        principal.SetClaim("session_id", row.SessionId);
        principal.SetClaim("auth_time", new DateTimeOffset(DateTime.SpecifyKind(row.ApprovedAtUtc!.Value, DateTimeKind.Utc)).ToUnixTimeSeconds());
        principal.SetClaims("amr", row.UsedMfa ? ["pwd", "otp"] : ["pwd"]);
        principal.SetDestinations(claim => claim.Type switch
        {
            "session_id" => [OpenIddictConstants.Destinations.AccessToken],
            "auth_time" or "amr" => [OpenIddictConstants.Destinations.IdentityToken],
            _ => claim.GetDestinations()
        });
        return new(principal, null);
    }
}
