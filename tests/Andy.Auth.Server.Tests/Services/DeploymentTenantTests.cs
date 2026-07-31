using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// andy-ahp#103. The tenant claim is what multi-tenant isolation rests on
/// downstream — andy-ahp keys row-level security, cache namespaces, object
/// keys and quotas on it — so these assert the two properties that make it
/// safe to trust: it comes from configuration only, and two deployments never
/// share one by accident.
/// </summary>
public class DeploymentTenantTests
{
    private static IConfiguration Configuration(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => e.Key, e => e.Value))
            .Build();

    [Fact]
    public void A_configured_tenant_id_is_used_verbatim()
    {
        var tenant = DeploymentTenant.Resolve(Configuration(
            (DeploymentTenant.ConfigurationKey, "3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
            ("OpenIddict:Issuer", "https://auth.example.test/")));

        tenant.TenantId.Should().Be(Guid.Parse("3f2504e0-4f89-41d3-9a0c-0305e82c3301"));
        tenant.Source.Should().Be(DeploymentTenant.ConfigurationKey);
    }

    [Fact]
    public void A_deployment_that_configures_no_tenant_derives_one_from_its_issuer()
    {
        var tenant = DeploymentTenant.Resolve(Configuration(
            ("OpenIddict:Issuer", "http://localhost:9100/auth")));

        tenant.TenantId.Should().NotBe(Guid.Empty);
        tenant.Source.Should().Be("OpenIddict:Issuer");
    }

    [Fact]
    public void The_derived_tenant_is_the_same_on_every_start_of_the_same_deployment()
    {
        // The whole point of deriving rather than generating: a restart must not
        // orphan every tenant-scoped row written before it.
        var first = DeploymentTenant.DeriveFromIssuer("http://localhost:9100/auth");
        var second = DeploymentTenant.DeriveFromIssuer("http://localhost:9100/auth");

        first.Should().Be(second);
    }

    [Fact]
    public void Two_deployments_never_derive_the_same_tenant()
    {
        // This is the failure the mechanism exists to prevent. An earlier
        // andy-ahp revision defaulted an absent tenant to Guid.Empty, which put
        // every such caller in one partition and made cross-tenant reads
        // possible; a shared derived default would reintroduce exactly that.
        var conductor = DeploymentTenant.DeriveFromIssuer("http://localhost:9100/auth");
        var standalone = DeploymentTenant.DeriveFromIssuer("https://localhost:5001");

        conductor.Should().NotBe(standalone);
        conductor.Should().NotBe(Guid.Empty);
        standalone.Should().NotBe(Guid.Empty);
    }

    [Theory]
    [InlineData("https://auth.example.test", "https://auth.example.test/")]
    [InlineData("https://auth.example.test", "HTTPS://Auth.Example.Test")]
    [InlineData("https://auth.example.test", "  https://auth.example.test  ")]
    public void One_deployment_written_two_ways_is_one_tenant(string left, string right)
    {
        DeploymentTenant.DeriveFromIssuer(left)
            .Should().Be(DeploymentTenant.DeriveFromIssuer(right));
    }

    [Fact]
    public void The_derived_tenant_is_a_name_based_uuid()
    {
        // RFC 4122 §4.3: version 5, variant 10x. Asserted so the value stays a
        // recognisable derived identifier rather than drifting into something
        // that looks random and invites regeneration.
        var bytes = DeploymentTenant.DeriveFromIssuer("http://localhost:9100/auth").ToByteArray();

        (bytes[7] & 0xF0).Should().Be(0x50);
        (bytes[8] & 0xC0).Should().Be(0x80);
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void A_configured_tenant_that_cannot_be_used_stops_the_deployment(string configured)
    {
        // Falling back to the derived id would hand the operator a working
        // server issuing a tenant they did not choose, discoverable only when
        // rows turned up under the wrong partition.
        var resolve = () => DeploymentTenant.Resolve(Configuration(
            (DeploymentTenant.ConfigurationKey, configured),
            ("OpenIddict:Issuer", "http://localhost:9100/auth")));

        resolve.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{DeploymentTenant.ConfigurationKey}*");
    }

    [Fact]
    public void A_deployment_with_neither_a_tenant_nor_an_issuer_has_no_identity_to_issue()
    {
        var resolve = () => DeploymentTenant.Resolve(Configuration());

        resolve.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void The_claim_value_round_trips_through_the_parse_resource_servers_use()
    {
        // andy-ahp does Guid.TryParse on the claim and rejects Guid.Empty.
        var tenant = DeploymentTenant.Resolve(Configuration(
            ("OpenIddict:Issuer", "http://localhost:9100/auth")));

        Guid.TryParse(tenant.ClaimValue, out var parsed).Should().BeTrue();
        parsed.Should().Be(tenant.TenantId).And.NotBe(Guid.Empty);
    }
}
