using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.Extensions.Hosting;

namespace Andy.Auth.Server.Tests.Configuration;

// Tests the IsEmbedded/IsDocker/IsLocalOrEmbedded helpers.
// These guard the split between "dev-only" (Swagger, permission
// bypass) and "non-production" (HTTPS metadata bypass) behaviors —
// mis-classifying a branch was the root cause of Conductor shipping
// with RBAC bypassed and developer exception pages enabled.
public class HostEnvironmentExtensionsTests
{
    [Theory]
    [InlineData("Embedded", true)]
    [InlineData("Development", false)]
    [InlineData("Docker", false)]
    [InlineData("Production", false)]
    [InlineData("Staging", false)]
    public void IsEmbedded_ReturnsExpected(string envName, bool expected)
    {
        var env = new FakeHostEnvironment { EnvironmentName = envName };
        env.IsEmbedded().Should().Be(expected);
    }

    [Theory]
    [InlineData("Docker", true)]
    [InlineData("Development", false)]
    [InlineData("Embedded", false)]
    [InlineData("Production", false)]
    public void IsDocker_ReturnsExpected(string envName, bool expected)
    {
        var env = new FakeHostEnvironment { EnvironmentName = envName };
        env.IsDocker().Should().Be(expected);
    }

    [Theory]
    [InlineData("Development", true)]
    [InlineData("Docker", true)]
    [InlineData("Embedded", true)]
    [InlineData("UAT", true)]
    [InlineData("Production", false)]
    public void IsLocalOrEmbedded_ReturnsTrueForAllNonProductionEnvs(string envName, bool expected)
    {
        var env = new FakeHostEnvironment { EnvironmentName = envName };
        env.IsLocalOrEmbedded().Should().Be(expected);
    }

    [Fact]
    public void IsEmbedded_IsCaseInsensitive()
    {
        var env = new FakeHostEnvironment { EnvironmentName = "embedded" };
        env.IsEmbedded().Should().BeTrue(
            "IHostEnvironment.IsEnvironment is documented as case-insensitive " +
            "and our helpers must not tighten that contract");
    }

    [Fact]
    public void IsEmbedded_NullEnvironmentThrows()
    {
        IHostEnvironment env = null!;
        var act = () => env.IsEmbedded();
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void EmbeddedEnvironmentName_MatchesConductorContract()
    {
        // Hard-coded here as a conscious duplicate of the Conductor-side
        // constant in ServiceEnvironment.swift. If either side changes
        // this string without the other, Embedded-mode branches silently
        // turn into no-ops and the app reverts to Development behavior.
        HostEnvironmentExtensions.EmbeddedEnvironmentName.Should().Be("Embedded");
    }

    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Andy.Auth.Server.Tests";
        public string ContentRootPath { get; set; } = "/";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
