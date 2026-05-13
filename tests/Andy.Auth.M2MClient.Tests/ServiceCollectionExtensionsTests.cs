// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using Andy.Auth.M2MClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Andy.Auth.M2MClient.Tests;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAndyAuthM2M_BindsOptionsFromAndyAuthSection()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AndyAuth:Authority"] = "https://example.test",
                ["AndyAuth:ClientId"] = "andy-tasks-api",
                ["AndyAuth:ClientSecretEnvVar"] = "ANDY_TASKS_API_SECRET",
                ["AndyAuth:Scope"] = "scp:urn:andy-settings-api",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAndyAuthM2M(config);
        using var provider = services.BuildServiceProvider();

        var opts = provider.GetRequiredService<IOptions<AndyAuthM2MOptions>>().Value;
        Assert.Equal("https://example.test", opts.Authority);
        Assert.Equal("andy-tasks-api", opts.ClientId);
        Assert.Equal("ANDY_TASKS_API_SECRET", opts.ClientSecretEnvVar);
        Assert.Equal("scp:urn:andy-settings-api", opts.Scope);
        Assert.True(opts.IsEnabled);
    }

    [Fact]
    public void AddAndyAuthM2M_RegistersProviderAsBothInterfaces()
    {
        var config = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAndyAuthM2M(config);
        using var provider = services.BuildServiceProvider();

        var token = provider.GetRequiredService<IServiceTokenProvider>();
        var refreshable = provider.GetRequiredService<IRefreshableServiceTokenProvider>();
        // Both interfaces must resolve to the same singleton — otherwise
        // ServiceBearerHandler's 401 retry refreshes a different cache
        // than GetTokenAsync reads.
        Assert.Same(token, refreshable);
    }

    [Fact]
    public void AddAndyAuthM2M_IsIdempotent()
    {
        var config = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAndyAuthM2M(config);
        services.AddAndyAuthM2M(config);
        services.AddAndyAuthM2M(config);
        using var provider = services.BuildServiceProvider();

        // Resolving must still succeed — TryAdd* keeps the first
        // registration, so consumers re-calling AddAndyAuthM2M() from
        // each client lib's Add{Name}Client() extension doesn't blow up.
        Assert.NotNull(provider.GetRequiredService<IServiceTokenProvider>());
    }

    [Fact]
    public void AddAndyAuthM2M_RegistersNamedHttpClient()
    {
        var config = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAndyAuthM2M(config);
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient(ClientCredentialsTokenProvider.HttpClientName);
        Assert.NotNull(client);
    }
}
