using Andy.Auth.Configuration;
using Andy.Auth.Providers;
using Andy.Auth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Extensions;

/// <summary>
/// Extension methods for adding Andy Auth to ASP.NET Core applications
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add Andy authentication with configuration from appsettings
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configuration">Application configuration</param>
    /// <param name="configSection">Configuration section name (default: "AndyAuth")</param>
    public static IServiceCollection AddAndyAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSection = "AndyAuth")
    {
        var options = new AndyAuthOptions();
        configuration.GetSection(configSection).Bind(options);

        return services.AddAndyAuth(options);
    }

    /// <summary>
    /// Add Andy authentication with explicit configuration
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Configuration action</param>
    public static IServiceCollection AddAndyAuth(
        this IServiceCollection services,
        Action<AndyAuthOptions> configure)
    {
        var options = new AndyAuthOptions();
        configure(options);

        return services.AddAndyAuth(options);
    }

    /// <summary>
    /// Add Andy authentication with options
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="options">Authentication options</param>
    public static IServiceCollection AddAndyAuth(
        this IServiceCollection services,
        AndyAuthOptions options)
    {
        // Register options
        services.AddSingleton(options);

        // Get the appropriate provider
        var provider = GetProvider(options);
        services.AddSingleton<IAuthProvider>(provider);

        // Configure authentication
        var authBuilder = services.AddAuthentication(authOptions =>
        {
            authOptions.DefaultAuthenticateScheme = options.AuthenticationScheme;
            authOptions.DefaultChallengeScheme = options.AuthenticationScheme;
            authOptions.DefaultScheme = options.AuthenticationScheme;
        });

        provider.ConfigureAuthentication(authBuilder, options);

        // Add authorization
        services.AddAuthorization();

        // Add current user service
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUserService, CurrentUserService>();

        // Add HttpClient for providers that need it (Clerk opaque tokens)
        services.AddHttpClient();

        return services;
    }

    /// <summary>
    /// Get the appropriate authentication provider based on options
    /// </summary>
    private static IAuthProvider GetProvider(AndyAuthOptions options)
    {
        return options.Provider switch
        {
            AuthProvider.AndyAuth => new AndyAuthProvider(),
            AuthProvider.AzureAD => new AzureAdProvider(),
            AuthProvider.Clerk => new ClerkProvider(),
            AuthProvider.Custom => throw new NotImplementedException(
                "Custom provider not implemented. Extend IAuthProvider and register it manually."),
            _ => throw new ArgumentException($"Unknown auth provider: {options.Provider}")
        };
    }
}
