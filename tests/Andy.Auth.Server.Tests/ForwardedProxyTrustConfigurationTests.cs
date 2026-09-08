using Andy.Auth.Server.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;

namespace Andy.Auth.Server.Tests;

public sealed class ForwardedProxyTrustConfigurationTests
{
    [Theory]
    [InlineData("KnownProxies:0", "invalid")]
    [InlineData("KnownNetworks:0", "10.0.0.0/999")]
    [InlineData("KnownNetworks:0", "0.0.0.0/0")]
    [InlineData("ForwardLimit", "0")]
    [InlineData("TrustAllProxies", "true")]
    public void InvalidProductionTrust_ThrowsWithoutClearingDefaults(string key, string value)
    {
        var options = new ForwardedHeadersOptions();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [key] = value }).Build();
        Assert.Throws<InvalidOperationException>(() => ForwardedProxyTrust.Configure(options, config, true));
        Assert.NotEmpty(options.KnownProxies);
    }

    [Fact]
    public void ExactIngressNetwork_DoesNotTrustOtherPrivatePeers()
    {
        var options = new ForwardedHeadersOptions();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["KnownNetworks:0"] = "10.24.7.0/24" }).Build();
        ForwardedProxyTrust.Configure(options, config, true);
        Assert.Single(options.KnownNetworks);
        Assert.True(options.KnownNetworks[0].Contains(System.Net.IPAddress.Parse("10.24.7.2")));
        Assert.False(options.KnownNetworks[0].Contains(System.Net.IPAddress.Parse("10.24.8.2")));
        Assert.Empty(options.KnownProxies);
    }
}
