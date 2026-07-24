using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Background service that periodically removes expired tokens, authorizations
/// and sessions from the database.
/// </summary>
public class TokenCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TokenCleanupService> _logger;
    private readonly TimeSpan _cleanupInterval;
    private readonly TimeSpan _retention;

    public TokenCleanupService(
        IServiceProvider serviceProvider,
        ILogger<TokenCleanupService> logger,
        IConfiguration configuration)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;

        // Default cleanup interval: 1 hour
        var intervalMinutes = configuration.GetValue<int>("OpenIddict:TokenCleanupIntervalMinutes", 60);
        _cleanupInterval = TimeSpan.FromMinutes(intervalMinutes);

        // How long invalid entries are kept before pruning. Non-zero so
        // redeemed codes and rotated refresh tokens remain visible to
        // reuse-detection and to the admin Tokens view.
        var retentionDays = configuration.GetValue<int>("OpenIddict:TokenRetentionDays", 14);
        _retention = TimeSpan.FromDays(retentionDays);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Token cleanup service started. Cleanup interval: {Interval}", _cleanupInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupTokensAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during token cleanup");
            }

            try
            {
                await Task.Delay(_cleanupInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown. Previously this propagated out of
                // ExecuteAsync as an unhandled TaskCanceledException on every
                // stop (andy-auth#156).
                break;
            }
        }
    }

    private async Task CleanupTokensAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var tokenManager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

        // OpenIddict's threshold is meant to sit in the past: it prunes entries
        // that are both invalid and older than it. Passing UtcNow deleted
        // authorization codes and refresh tokens the instant they were redeemed
        // or expired, destroying the trail reuse/replay detection relies on and
        // emptying the admin Tokens view (andy-auth#156). Keep a retention
        // window instead.
        var threshold = DateTimeOffset.UtcNow - _retention;

        // Prune expired tokens
        var tokensPruned = await tokenManager.PruneAsync(threshold, cancellationToken);
        if (tokensPruned > 0)
        {
            _logger.LogInformation("Pruned {Count} expired tokens", tokensPruned);
        }

        // Prune expired authorizations
        var authorizationsPruned = await authorizationManager.PruneAsync(threshold, cancellationToken);
        if (authorizationsPruned > 0)
        {
            _logger.LogInformation("Pruned {Count} expired authorizations", authorizationsPruned);
        }

        // Close out lapsed sessions. SessionService.CleanupExpiredSessionsAsync
        // existed but was referenced only from tests, so UserSessions grew
        // without bound and expired rows were never marked (andy-auth#154).
        var sessionService = scope.ServiceProvider.GetRequiredService<SessionService>();
        await sessionService.CleanupExpiredSessionsAsync();
    }
}
