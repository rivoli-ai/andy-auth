using System.Text.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Andy.Auth.Server.Services.Ciba;

public static class CibaRegistration
{
    public static void AddCibaServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<CibaOptions>().Bind(configuration.GetSection("OpenIddict:AdvancedFlows:CIBA"))
            .Validate(options => options.IsValid(), "CIBA requires bounded lifetimes and valid VAPID keys, contact and trusted push origins.").ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<CibaPushDelivery>();
        services.AddHttpClient(CibaPushDelivery.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(5);
            client.MaxResponseContentBufferSize = 16 * 1024;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        if (configuration.GetValue<bool>("OpenIddict:AdvancedFlows:CIBA:Enabled"))
        {
            if (string.IsNullOrWhiteSpace(configuration["RateLimiting:RedisConnectionString"]))
                throw new InvalidOperationException("CIBA requires shared Redis for notification throttling.");
            services.AddScoped<CibaService>();
            services.AddHostedService<CibaPushWorker>();
        }
    }
    public static void AddCibaFlow(this OpenIddictServerBuilder server, IConfiguration configuration)
    {
        if (!configuration.GetValue<bool>("OpenIddict:AdvancedFlows:CIBA:Enabled")) return;
        if (!Uri.TryCreate(configuration["OpenIddict:Issuer"], UriKind.Absolute, out var issuerUri) || issuerUri.Scheme != "https")
            throw new InvalidOperationException("CIBA requires a canonical HTTPS issuer.");
        server.AllowCustomFlow(CibaOptions.GrantType);
        server.AddEventHandler<HandleConfigurationRequestContext>(handler => handler.SetOrder(int.MaxValue - 1000).UseInlineHandler(context =>
        {
            var issuer = context.Issuer ?? throw new InvalidOperationException("CIBA requires an issuer");
            context.Metadata["backchannel_authentication_endpoint"] = new Uri(new Uri(issuer.AbsoluteUri.TrimEnd('/') + "/"), "connect/bc-authorize").AbsoluteUri;
            context.Metadata["backchannel_token_delivery_modes_supported"] = JsonSerializer.SerializeToElement(new[] { "poll" });
            context.Metadata["backchannel_user_code_parameter_supported"] = false;
            return ValueTask.CompletedTask;
        }));
    }
}
