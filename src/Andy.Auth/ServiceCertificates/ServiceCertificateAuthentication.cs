using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Andy.Auth.ServiceCertificates;

public static class ServiceCertificateAuthentication
{
    public const string Scheme = "Andy.Service";
    public const string CertificateScheme = "Andy.ClientCertificate";

    /// <summary>Registers an explicit service-only scheme. Existing user authentication defaults are preserved.</summary>
    public static AuthenticationBuilder AddAndyServiceAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ServiceCertificateOptions>().Bind(configuration.GetSection(ServiceCertificateOptions.SectionName))
            .Validate(options => options.IsValid(), "Invalid service certificate configuration.").ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ServiceCertificateValidator>();
        services.AddTransient<RotatingServiceCertificateHandler>();
        return services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, ServiceCertificateHandler>(CertificateScheme, _ => { })
            .AddPolicyScheme(Scheme, "Service authentication", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    var settings = context.RequestServices.GetRequiredService<IOptionsMonitor<ServiceCertificateOptions>>().CurrentValue;
                    return settings.EffectiveMode switch
                    {
                        ServiceAuthenticationMode.Jwt => settings.JwtScheme,
                        ServiceAuthenticationMode.ClientCertificate => CertificateScheme,
                        // Actual TLS connection state only. Never trust a forwarded certificate header.
                        _ => context.Connection.ClientCertificate is not null ? CertificateScheme : settings.JwtScheme
                    };
                };
            });
    }
}

internal sealed class ServiceCertificateHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder, ServiceCertificateValidator validator,
    IOptionsMonitor<ServiceCertificateOptions> configuration) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private bool unavailable;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.IsHttps) return AuthenticateResult.Fail("TLS is required for service certificates.");
        var certificate = await Context.Connection.GetClientCertificateAsync(Context.RequestAborted);
        if (certificate is null) return AuthenticateResult.NoResult();
        var validation = validator.Validate(certificate);
        unavailable = validation.Unavailable;
        if (!validation.Succeeded)
        {
            ServiceCertificateMetrics.Rejected.Add(1, new KeyValuePair<string, object?>("reason", validation.Error));
            return AuthenticateResult.Fail(validation.Error!);
        }
        var claims = new[]
        {
            new Claim("sub", validation.Subject!),
            new Claim(ClaimTypes.NameIdentifier, validation.Subject!),
            new Claim("client_id", validation.Subject!),
            new Claim("service_identity", validation.Identity!),
            new Claim("provider", configuration.CurrentValue.SubjectProvider),
            new Claim("authentication_method", "mtls"),
            new Claim("certificate_sha256", certificate.GetCertHashString(HashAlgorithmName.SHA256))
        };
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name)), Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = unavailable ? StatusCodes.Status503ServiceUnavailable : StatusCodes.Status401Unauthorized;
        Response.Headers.CacheControl = "no-store";
        if (unavailable) Response.Headers.RetryAfter = "5";
        else Response.Headers.WWWAuthenticate = "MutualTLS";
        return Task.CompletedTask;
    }
}
