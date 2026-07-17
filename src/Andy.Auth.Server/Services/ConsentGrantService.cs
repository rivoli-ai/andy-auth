using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Owns the lifecycle of <see cref="ConsentGrant"/> records: the short-lived,
/// single-use, server-side proof that a user just approved an OAuth consent
/// request.
/// <para>
/// Issue #124: the authorization endpoint previously trusted a
/// client-controlled <c>consent_granted=true</c> query marker as proof of
/// consent, which any client could forge to skip the consent screen and be
/// issued every requested scope. This service replaces that marker with state
/// that is created only by the consent UI (<c>ConsentController</c>) and
/// validated + consumed by the authorization endpoint
/// (<c>AuthorizationController</c>).
/// </para>
/// <para>
/// Security invariants enforced by <see cref="ConsumeAsync"/>:
/// <list type="bullet">
/// <item>The grant must exist and be referenced by its unguessable id.</item>
/// <item>It must not have been consumed already (replay protection).</item>
/// <item>It must not have expired (short TTL).</item>
/// <item>It must be bound to the same user, client, redirect URI and exact
/// requested-scope set as the incoming request (tamper protection).</item>
/// <item>Only the recorded approved scope subset is ever returned — never the
/// raw requested scopes.</item>
/// </list>
/// </para>
/// </summary>
public class ConsentGrantService
{
    /// <summary>
    /// Default lifetime of a consent grant. It only needs to survive the
    /// browser redirect from the consent screen back to the authorization
    /// endpoint, so it is intentionally short.
    /// </summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(5);

    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<ConsentGrantService> _logger;

    public ConsentGrantService(ApplicationDbContext dbContext, ILogger<ConsentGrantService> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    /// <summary>
    /// Creates and persists a new consent grant bound to the given user,
    /// client, redirect URI and requested-scope set, recording the approved
    /// scope subset. Returns the persisted grant (its <see cref="ConsentGrant.GrantId"/>
    /// is the value handed back to the browser).
    /// </summary>
    public async Task<ConsentGrant> CreateAsync(
        string userId,
        string clientId,
        string? redirectUri,
        IEnumerable<string> requestedScopes,
        IEnumerable<string> grantedScopes,
        CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var grant = new ConsentGrant
        {
            GrantId = GenerateGrantId(),
            UserId = userId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            CreatedAt = now,
            ExpiresAt = now.Add(DefaultLifetime)
        };
        grant.SetRequestedScopes(requestedScopes);
        grant.SetGrantedScopes(grantedScopes);

        _dbContext.ConsentGrants.Add(grant);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return grant;
    }

    /// <summary>
    /// Validates and consumes the consent grant referenced by
    /// <paramref name="consentId"/>. On success the grant is marked consumed
    /// (single use) and the approved scope subset is returned. On any failure
    /// (missing, replayed, expired, or bound to a different
    /// user/client/redirect/scope set) a failure result is returned and the
    /// caller should fall back to displaying the consent screen.
    /// </summary>
    public async Task<ConsentGrantConsumeResult> ConsumeAsync(
        string? consentId,
        string userId,
        string clientId,
        string? redirectUri,
        IReadOnlyCollection<string> requestedScopes,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(consentId))
        {
            return ConsentGrantConsumeResult.Fail(ConsentGrantConsumeStatus.NotFound);
        }

        var grant = await _dbContext.ConsentGrants
            .FirstOrDefaultAsync(g => g.GrantId == consentId, cancellationToken);

        if (grant == null)
        {
            _logger.LogWarning(
                "Consent grant not found for user {UserId}, client {ClientId}.", userId, clientId);
            return ConsentGrantConsumeResult.Fail(ConsentGrantConsumeStatus.NotFound);
        }

        var now = DateTime.UtcNow;

        // Replay: a grant may only be consumed once.
        if (grant.ConsumedAt != null)
        {
            _logger.LogWarning(
                "Consent grant replay rejected for user {UserId}, client {ClientId} (already consumed at {ConsumedAt}).",
                userId, clientId, grant.ConsumedAt);
            return ConsentGrantConsumeResult.Fail(ConsentGrantConsumeStatus.Replayed);
        }

        // Expiry.
        if (grant.ExpiresAt <= now)
        {
            _logger.LogWarning(
                "Consent grant rejected for user {UserId}, client {ClientId} (expired at {ExpiresAt}).",
                userId, clientId, grant.ExpiresAt);
            return ConsentGrantConsumeResult.Fail(ConsentGrantConsumeStatus.Expired);
        }

        // Binding checks: the grant must belong to this user, client and
        // redirect URI, and the requested-scope set must be exactly the set the
        // user saw and approved against. Any mismatch means the request was
        // tampered with after consent.
        var requestedSet = new HashSet<string>(requestedScopes, StringComparer.Ordinal);
        var boundOk =
            string.Equals(grant.UserId, userId, StringComparison.Ordinal) &&
            string.Equals(grant.ClientId, clientId, StringComparison.Ordinal) &&
            string.Equals(grant.RedirectUri, redirectUri, StringComparison.Ordinal) &&
            requestedSet.SetEquals(grant.RequestedScopesList);

        if (!boundOk)
        {
            _logger.LogWarning(
                "Consent grant binding mismatch (user/client/redirect/scope tampering) for user {UserId}, client {ClientId}.",
                userId, clientId);
            return ConsentGrantConsumeResult.Fail(ConsentGrantConsumeStatus.BindingMismatch);
        }

        // Consume (single use) before issuing anything.
        grant.ConsumedAt = now;
        await _dbContext.SaveChangesAsync(cancellationToken);

        // Issue only the approved subset, constrained to the current request.
        var approved = grant.GrantedScopesList
            .Where(s => requestedSet.Contains(s))
            .ToList();

        return ConsentGrantConsumeResult.Ok(approved);
    }

    /// <summary>
    /// Generates a cryptographically-random, URL-safe identifier. The value is
    /// the only piece of consent state that transits the (untrusted) client, so
    /// it must be unguessable.
    /// </summary>
    public static string GenerateGrantId()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }
}

/// <summary>
/// Outcome discriminator for <see cref="ConsentGrantService.ConsumeAsync"/>.
/// </summary>
public enum ConsentGrantConsumeStatus
{
    /// <summary>The grant was valid and has been consumed.</summary>
    Success,

    /// <summary>No <c>consent_id</c> was supplied, or no such grant exists.</summary>
    NotFound,

    /// <summary>The grant had already been consumed (replay).</summary>
    Replayed,

    /// <summary>The grant had expired.</summary>
    Expired,

    /// <summary>The grant was bound to a different user, client, redirect URI or requested-scope set.</summary>
    BindingMismatch
}

/// <summary>
/// Result of consuming a consent grant.
/// </summary>
public sealed class ConsentGrantConsumeResult
{
    /// <summary>The outcome of the consume attempt.</summary>
    public ConsentGrantConsumeStatus Status { get; init; }

    /// <summary>
    /// The approved scope subset when <see cref="Status"/> is
    /// <see cref="ConsentGrantConsumeStatus.Success"/>; otherwise empty.
    /// </summary>
    public IReadOnlyList<string> ApprovedScopes { get; init; } = Array.Empty<string>();

    /// <summary>Whether the grant was valid and consumed.</summary>
    public bool Succeeded => Status == ConsentGrantConsumeStatus.Success;

    internal static ConsentGrantConsumeResult Fail(ConsentGrantConsumeStatus status) =>
        new() { Status = status };

    internal static ConsentGrantConsumeResult Ok(IReadOnlyList<string> approvedScopes) =>
        new() { Status = ConsentGrantConsumeStatus.Success, ApprovedScopes = approvedScopes };
}
