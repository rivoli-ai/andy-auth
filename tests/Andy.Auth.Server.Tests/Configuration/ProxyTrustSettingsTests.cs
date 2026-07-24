using System.Net;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Xunit;

namespace Andy.Auth.Server.Tests.Configuration;

/// <summary>
/// andy-auth#125. Startup used to clear KnownNetworks and KnownProxies
/// unconditionally, which accepts forwarding headers from any peer. The
/// resolved address keys the rate limiter, attributes account lockout, and
/// lands in audit records — so whoever can set it can evade login and token
/// limits and misattribute the evidence.
/// </summary>
public class ProxyTrustSettingsTests
{
    [Fact]
    public void Unconfigured_LeavesFrameworkDefaults()
    {
        // ASP.NET Core's default trusts loopback only, which is exactly right
        // for local dev and Conductor's embedded mode (proxy on localhost).
        var options = new ForwardedHeadersOptions();
        var before = options.KnownNetworks.Count + options.KnownProxies.Count;

        var description = new ProxyTrustSettings().Apply(options);

        (options.KnownNetworks.Count + options.KnownProxies.Count).Should().Be(before);
        description.Should().Contain("loopback only");
    }

    [Fact]
    public void TrustAllProxies_ClearsTheAllowListAndSaysSoLoudly()
    {
        // Still available — Railway's edge appends the real client address —
        // but now an explicit, greppable decision rather than a silent default.
        var options = new ForwardedHeadersOptions();

        var description = new ProxyTrustSettings { TrustAllProxies = true }.Apply(options);

        options.KnownNetworks.Should().BeEmpty();
        options.KnownProxies.Should().BeEmpty();
        description.Should().Contain("any peer");
        description.Should().Contain("MUST overwrite or append");
    }

    [Fact]
    public void ExplicitProxies_ReplaceTheDefaults()
    {
        var options = new ForwardedHeadersOptions();

        new ProxyTrustSettings
        {
            KnownProxies = new[] { "10.1.2.3", "::1" },
        }.Apply(options);

        options.KnownProxies.Should().BeEquivalentTo(new[]
        {
            IPAddress.Parse("10.1.2.3"),
            IPAddress.Parse("::1"),
        });
        options.KnownNetworks.Should().BeEmpty();
    }

    [Fact]
    public void ExplicitNetworks_AreParsedFromCidr()
    {
        var options = new ForwardedHeadersOptions();

        new ProxyTrustSettings
        {
            KnownNetworks = new[] { "10.0.0.0/8", "192.168.0.0/16" },
        }.Apply(options);

        options.KnownNetworks.Should().HaveCount(2);
        options.KnownNetworks[0].Prefix.Should().Be(IPAddress.Parse("10.0.0.0"));
        options.KnownNetworks[0].PrefixLength.Should().Be(8);
    }

    [Fact]
    public void ForwardLimit_DefaultsToOneHop()
    {
        // One means "the address the edge appended". Raising it starts trusting
        // entries the client may have supplied.
        var options = new ForwardedHeadersOptions();

        new ProxyTrustSettings().Apply(options);

        options.ForwardLimit.Should().Be(1);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("999.1.1.1")]
    public void MalformedProxyAddress_FailsFast(string value)
    {
        // A typo silently dropping a proxy from the allow-list would quietly
        // widen or narrow the trust boundary; refuse to start instead.
        var act = () => new ProxyTrustSettings { KnownProxies = new[] { value } }
            .Apply(new ForwardedHeadersOptions());

        act.Should().Throw<InvalidOperationException>().WithMessage("*KnownProxies*");
    }

    [Theory]
    [InlineData("10.0.0.0")]        // no prefix length
    [InlineData("10.0.0.0/abc")]
    [InlineData("10.0.0.0/33")]     // out of range for IPv4
    [InlineData("::1/129")]         // out of range for IPv6
    public void MalformedNetwork_FailsFast(string value)
    {
        var act = () => new ProxyTrustSettings { KnownNetworks = new[] { value } }
            .Apply(new ForwardedHeadersOptions());

        act.Should().Throw<InvalidOperationException>().WithMessage("*KnownNetworks*");
    }
}
