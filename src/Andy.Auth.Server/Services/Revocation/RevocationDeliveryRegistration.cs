using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Andy.Auth.Server.Services.Revocation;

public static class RevocationDeliveryRegistration
{
    public static void AddRevocationDelivery(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RevocationDeliveryOptions>().Bind(configuration.GetSection("RevocationDelivery"))
            .Validate(options => options.IsValid(), "Enabled revocation delivery requires unique audiences and trusted absolute HTTPS endpoints.")
            .ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<RevocationDispatcher>();
        services.AddHttpClient(RevocationDispatcher.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(5);
            client.MaxResponseContentBufferSize = 16 * 1024;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        if (configuration.GetValue<bool>("RevocationDelivery:Enabled"))
            services.AddHostedService<RevocationDeliveryWorker>();
    }
}
