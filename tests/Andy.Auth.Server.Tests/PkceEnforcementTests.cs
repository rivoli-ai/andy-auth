using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Pins andy-auth#46: PKCE is required server-wide for the
// authorization-code flow. Asserts the configured OpenIddict
// server options instead of poking the HTTP surface, so the
// test does not depend on Postgres being up or on cookie
// state from an authenticated session.
public class PkceEnforcementTests
{
    [Fact]
    public void OpenIddictServerOptions_RequireProofKeyForCodeExchange_IsTrue()
    {
        using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.UseEnvironment("Development"));
        using var scope = factory.Services.CreateScope();

        var options = scope.ServiceProvider
            .GetRequiredService<IOptions<OpenIddictServerOptions>>()
            .Value;

        options.RequireProofKeyForCodeExchange.Should().BeTrue(
            "andy-auth#46 closes by enforcing PKCE for every auth-code " +
            "client at the server level — public and confidential alike.");
    }
}
