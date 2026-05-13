// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using Andy.Auth.M2MClient;
using Xunit;

namespace Andy.Auth.M2MClient.Tests;

public sealed class AndyAuthM2MOptionsTests
{
    [Fact]
    public void ResolveTokenEndpoint_PrefersExplicit()
    {
        var opts = new AndyAuthM2MOptions
        {
            Authority = "https://localhost:5001",
            TokenEndpoint = "http://localhost:9100/auth/connect/token",
        };

        Assert.Equal(new Uri("http://localhost:9100/auth/connect/token"), opts.ResolveTokenEndpoint());
    }

    [Fact]
    public void ResolveTokenEndpoint_DerivesFromAuthority_WhenExplicitMissing()
    {
        var opts = new AndyAuthM2MOptions { Authority = "https://localhost:5001" };

        Assert.Equal(new Uri("https://localhost:5001/connect/token"), opts.ResolveTokenEndpoint());
    }

    [Fact]
    public void ResolveTokenEndpoint_StripsTrailingSlash_BeforeDeriving()
    {
        var opts = new AndyAuthM2MOptions { Authority = "https://localhost:5001/" };

        Assert.Equal(new Uri("https://localhost:5001/connect/token"), opts.ResolveTokenEndpoint());
    }

    [Fact]
    public void ResolveTokenEndpoint_Throws_WhenBothMissing()
    {
        var opts = new AndyAuthM2MOptions();

        var ex = Assert.Throws<InvalidOperationException>(() => opts.ResolveTokenEndpoint());
        Assert.Contains("[M2M-OPTS-NOENDPOINT]", ex.Message);
    }

    [Fact]
    public void IsEnabled_True_WhenClientIdAndEnvVarAndAuthorityPresent()
    {
        var opts = new AndyAuthM2MOptions
        {
            Authority = "https://localhost:5001",
            ClientId = "andy-tasks-api",
            ClientSecretEnvVar = "ANDY_TASKS_API_SECRET",
        };

        Assert.True(opts.IsEnabled);
    }

    [Fact]
    public void IsEnabled_True_WithExplicitTokenEndpointAndNoAuthority()
    {
        var opts = new AndyAuthM2MOptions
        {
            TokenEndpoint = "http://localhost:9100/auth/connect/token",
            ClientId = "andy-tasks-api",
            ClientSecretEnvVar = "ANDY_TASKS_API_SECRET",
        };

        Assert.True(opts.IsEnabled);
    }

    [Fact]
    public void IsEnabled_False_WhenClientIdMissing()
    {
        var opts = new AndyAuthM2MOptions
        {
            Authority = "https://localhost:5001",
            ClientSecretEnvVar = "ANDY_TASKS_API_SECRET",
        };

        Assert.False(opts.IsEnabled);
    }

    [Fact]
    public void IsEnabled_False_WhenSecretEnvVarMissing()
    {
        var opts = new AndyAuthM2MOptions
        {
            Authority = "https://localhost:5001",
            ClientId = "andy-tasks-api",
        };

        Assert.False(opts.IsEnabled);
    }
}
