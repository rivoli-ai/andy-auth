using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Reconciles orphaned Dynamic Client Registration records (#120).
///
/// DCR registration persists an OpenIddict application, the initial-access-token
/// consumption, a registration access token (RAT), and DCR metadata. Although
/// the registration path now commits all of these in a single transaction, a
/// process that was interrupted before that fix shipped — or any future partial
/// failure outside the transaction boundary — can leave an OpenIddict
/// application whose client_id carries the DCR-issued prefix but has no
/// <see cref="DynamicClientRegistration"/> metadata. At runtime such an
/// application is fail-closed (it cannot authorize or mint tokens, see
/// AuthorizationController.IsDcrClientActiveAsync); this routine sweeps them
/// away so they do not accumulate.
/// </summary>
public class DcrReconciliationService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<DcrReconciliationService> _logger;

    public DcrReconciliationService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        ILogger<DcrReconciliationService> logger)
    {
        _context = context;
        _applicationManager = applicationManager;
        _logger = logger;
    }

    /// <summary>
    /// Identifies and removes orphaned DCR artifacts:
    ///   * OpenIddict applications with a DCR-issued client_id but no DCR
    ///     metadata (the incomplete-registration orphan), and
    ///   * registration access tokens whose client_id has neither a matching
    ///     application nor DCR metadata.
    /// </summary>
    /// <returns>The number of orphaned OpenIddict applications removed.</returns>
    public async Task<int> ReconcileAsync(CancellationToken cancellationToken = default)
    {
        // Snapshot the client_ids that DO have committed DCR metadata. Anything
        // DCR-shaped outside this set is an orphan.
        var registeredClientIds = await _context.DynamicClientRegistrations
            .AsNoTracking()
            .Select(d => d.ClientId)
            .ToListAsync(cancellationToken);
        var registeredSet = new HashSet<string>(registeredClientIds, StringComparer.Ordinal);

        var orphanClientIds = new List<string>();

        await foreach (var application in _applicationManager.ListAsync(cancellationToken: cancellationToken))
        {
            var clientId = await _applicationManager.GetClientIdAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(clientId) || !DcrService.IsDcrIssuedClientId(clientId))
            {
                continue;
            }

            if (registeredSet.Contains(clientId))
            {
                continue;
            }

            // TOCTOU guard for multi-replica / rolling deploys: `registeredSet`
            // was snapshotted before this ListAsync enumeration began, so a
            // registration that committed atomically on ANOTHER replica in the
            // meantime would appear here as a false orphan. Re-check the LIVE
            // metadata table immediately before deleting; only an application
            // that STILL has no DCR metadata is a genuine orphan.
            var stillHasNoMetadata = !await _context.DynamicClientRegistrations
                .AsNoTracking()
                .AnyAsync(d => d.ClientId == clientId, cancellationToken);
            if (!stillHasNoMetadata)
            {
                continue;
            }

            _logger.LogWarning(
                "Reconciliation: removing orphaned DCR application {ClientId} " +
                "(no DynamicClientRegistration metadata).",
                clientId);

            await _applicationManager.DeleteAsync(application, cancellationToken);
            orphanClientIds.Add(clientId);
        }

        // Sweep registration access tokens left behind by a partial write:
        // any RAT whose client_id has neither committed DCR metadata nor a
        // surviving application. (Applications just deleted above are included.)
        var deletedAppClientIds = new HashSet<string>(orphanClientIds, StringComparer.Ordinal);
        var orphanTokens = await _context.RegistrationAccessTokens
            .Where(t => !_context.DynamicClientRegistrations.Any(d => d.ClientId == t.ClientId))
            .ToListAsync(cancellationToken);

        var removedTokenCount = 0;
        foreach (var token in orphanTokens)
        {
            // Only remove a RAT once we are sure no live application backs it.
            if (deletedAppClientIds.Contains(token.ClientId)
                || await _applicationManager.FindByClientIdAsync(token.ClientId, cancellationToken) == null)
            {
                _context.RegistrationAccessTokens.Remove(token);
                removedTokenCount++;
            }
        }

        if (removedTokenCount > 0)
        {
            await _context.SaveChangesAsync(cancellationToken);
        }

        if (orphanClientIds.Count > 0 || removedTokenCount > 0)
        {
            _logger.LogInformation(
                "Reconciliation complete: removed {AppCount} orphaned DCR application(s) " +
                "and {TokenCount} orphaned registration access token(s).",
                orphanClientIds.Count, removedTokenCount);
        }

        return orphanClientIds.Count;
    }
}
