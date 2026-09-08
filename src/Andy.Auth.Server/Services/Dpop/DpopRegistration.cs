using System.Text.Json;
using Andy.Auth.Dpop;
using Microsoft.AspNetCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Andy.Auth.Server.Services.Dpop;

public static class DpopRegistration
{
    public static void AddDpopServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<DpopOptions>().Bind(configuration.GetSection("OpenIddict:AdvancedFlows:DPoP"))
            .Validate(options => options.ProofLifetime >= TimeSpan.FromSeconds(1) && options.ProofLifetime <= TimeSpan.FromMinutes(5),
                "DPoP proof lifetime must be between one second and five minutes.").ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<DpopNonceService>();
        if (configuration.GetValue<bool>("OpenIddict:AdvancedFlows:DPoP:Enabled"))
        {
            if (string.IsNullOrWhiteSpace(configuration["RateLimiting:RedisConnectionString"]))
                throw new InvalidOperationException("DPoP requires a shared Redis replay store through RateLimiting:RedisConnectionString.");
            services.TryAddSingleton<IDpopReplayStore, RedisDpopReplayStore>();
            services.AddScoped<DpopProofValidator>();
        }
    }

    public static void AddDpopHandlers(this OpenIddictServerBuilder options, IConfiguration configuration)
    {
        var enabled = configuration.GetValue<bool>("OpenIddict:AdvancedFlows:DPoP:Enabled");
        options.AddEventHandler<ProcessAuthenticationContext>(handler => handler
            .SetOrder(OpenIddictServerHandlers.ValidateClientSecret.Descriptor.Order + 500).UseScopedHandler<ValidateTokenProof>());
        options.AddEventHandler<ProcessAuthenticationContext>(handler => handler.SetOrder(int.MaxValue - 1000).UseScopedHandler<CaptureArtifactBinding>());
        options.AddEventHandler<ProcessSignInContext>(handler => handler
            .SetOrder(OpenIddictServerHandlers.ValidateSignInDemand.Descriptor.Order + 500).UseScopedHandler<AttachProofBinding>());
        options.AddEventHandler<ValidateAuthorizationRequestContext>(handler => handler.SetOrder(int.MaxValue - 1000).UseInlineHandler(context =>
        {
            var key = (string?)context.Request["dpop_jkt"];
            if (key != null && (!enabled || key.Length != 43 || key.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not '-' and not '_')))
                context.Reject(OpenIddictConstants.Errors.InvalidRequest, "dpop_jkt must be a SHA-256 public-key thumbprint and DPoP must be enabled.");
            return ValueTask.CompletedTask;
        }));
        options.AddEventHandler<ApplyTokenResponseContext>(handler => handler.SetOrder(int.MinValue + 1000).UseInlineHandler(context =>
        {
            if (!string.IsNullOrEmpty(context.Response.AccessToken) && context.Transaction.GetProperty<string>(DpopBinding.Key) != null)
                context.Response.TokenType = "DPoP";
            return ValueTask.CompletedTask;
        }));
        options.AddEventHandler<HandleIntrospectionRequestContext>(handler => handler.SetOrder(int.MaxValue - 2000).UseScopedHandler<LiveIntrospection>());
        options.AddEventHandler<HandleIntrospectionRequestContext>(handler => handler.SetOrder(int.MaxValue - 1000).UseInlineHandler(context =>
        {
            var confirmation = context.GenericTokenPrincipal?.GetClaim("cnf");
            if (confirmation != null)
            {
                using var json = JsonDocument.Parse(confirmation);
                context.Claims["cnf"] = json.RootElement.Clone();
                if (json.RootElement.TryGetProperty("jkt", out _)) context.TokenType = "DPoP";
            }
            return ValueTask.CompletedTask;
        }));
        if (enabled)
            options.AddEventHandler<HandleConfigurationRequestContext>(handler => handler.SetOrder(int.MaxValue - 1000).UseInlineHandler(context =>
            {
                context.Metadata["dpop_signing_alg_values_supported"] = JsonSerializer.SerializeToElement(new[] { "ES256", "RS256" });
                return ValueTask.CompletedTask;
            }));
    }

    public static void AddDpopBindingValidation(this OpenIddictValidationBuilder options) =>
        options.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(handler => handler.SetOrder(int.MaxValue - 1000)
            .UseInlineHandler(context =>
            {
                var http = context.Transaction.GetHttpRequest()?.HttpContext;
                if (context.AccessTokenPrincipal != null && (http is null
                    ? context.AccessTokenPrincipal.HasClaim(claim => claim.Type == "cnf")
                    : !DpopHttpProof.BindingSatisfied(http, context.AccessTokenPrincipal, context.AccessToken!)))
                {
                    if (http != null) DpopHttpProof.Reject(http, "invalid_token");
                    context.Reject(OpenIddictConstants.Errors.InvalidToken, "A matching proof of possession is required.");
                }
                return ValueTask.CompletedTask;
            }));
}
