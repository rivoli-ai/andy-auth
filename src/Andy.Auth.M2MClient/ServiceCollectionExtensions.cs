// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Andy.Auth.M2MClient;

/// <summary>
/// DI registration helpers for the M2M token provider + bearer handler.
/// Consumer client libraries (Andy.Settings.Client, Andy.Rbac.Client,
/// Andy.Containers.Client, …) opt in by calling
/// <see cref="AddAndyAuthM2M"/> on the host's service collection, then
/// chain <see cref="AddBearerFromAndyAuthM2M"/> onto each outbound
/// <see cref="IHttpClientBuilder"/> that needs an M2M-stamped bearer.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="ClientCredentialsTokenProvider"/> + its
    /// transitive dependencies (named HttpClient, <see cref="ServiceBearerHandler"/>,
    /// <see cref="TimeProvider"/>). Idempotent — safe to call from
    /// multiple consumer-client registrations.
    /// </summary>
    /// <param name="services">DI container to mutate.</param>
    /// <param name="configuration">Configuration root; the <c>AndyAuth</c> section is bound.</param>
    public static IServiceCollection AddAndyAuthM2M(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services
            .AddOptions<AndyAuthM2MOptions>()
            .Bind(configuration.GetSection(AndyAuthM2MOptions.SectionName));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ClientCredentialsTokenProvider>();
        services.TryAddSingleton<IServiceTokenProvider>(sp =>
            sp.GetRequiredService<ClientCredentialsTokenProvider>());
        services.TryAddSingleton<IRefreshableServiceTokenProvider>(sp =>
            sp.GetRequiredService<ClientCredentialsTokenProvider>());
        services.TryAddTransient<ServiceBearerHandler>();
        services.AddHttpClient(ClientCredentialsTokenProvider.HttpClientName);

        return services;
    }

    /// <summary>
    /// Chains <see cref="ServiceBearerHandler"/> onto an
    /// <see cref="IHttpClientBuilder"/> so every outbound request from
    /// that named HttpClient carries an M2M-acquired bearer token.
    /// Requires <see cref="AddAndyAuthM2M"/> to have been called.
    /// </summary>
    public static IHttpClientBuilder AddBearerFromAndyAuthM2M(this IHttpClientBuilder builder)
        => builder.AddHttpMessageHandler<ServiceBearerHandler>();
}
