using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace Andy.Auth.Server.Tests;

public sealed class TokenLifetimePolicyTests
{
    [Fact]
    public void OpenIddictServerOptions_UseExplicitShortJwtLifetime()
    {
        using var factory = new CustomWebApplicationFactory();
        using var scope = factory.Services.CreateScope();

        var options = scope.ServiceProvider
            .GetRequiredService<IOptions<OpenIddictServerOptions>>()
            .Value;

        options.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(5));
        options.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(14));
    }
}
