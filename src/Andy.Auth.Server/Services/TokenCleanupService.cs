using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Background service that periodically removes expired tokens and authorizations from the database.
/// </summary>
public class TokenCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TokenCleanupService> _logger;
    private readonly TimeSpan _cleanupInterval;

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

            await Task.Delay(_cleanupInterval, stoppingToken);
        }
    }

    private async Task CleanupTokensAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var tokenManager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

        // Prune expired tokens
        var tokensPruned = await tokenManager.PruneAsync(DateTimeOffset.UtcNow, cancellationToken);
        if (tokensPruned > 0)
        {
            _logger.LogInformation("Pruned {Count} expired tokens", tokensPruned);
        }

        // Prune expired authorizations
        var authorizationsPruned = await authorizationManager.PruneAsync(DateTimeOffset.UtcNow, cancellationToken);
        if (authorizationsPruned > 0)
        {
            _logger.LogInformation("Pruned {Count} expired authorizations", authorizationsPruned);
        }
    }
}
