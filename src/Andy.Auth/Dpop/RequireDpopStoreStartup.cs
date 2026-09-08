using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Andy.Auth.Dpop;

public sealed class RequireDpopStoreStartup(IServiceProvider services) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = services.CreateScope();
        _ = scope.ServiceProvider.GetRequiredService<IDpopReplayStore>();
        _ = scope.ServiceProvider.GetRequiredService<DpopProofValidator>();
        return Task.CompletedTask;
    }
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
