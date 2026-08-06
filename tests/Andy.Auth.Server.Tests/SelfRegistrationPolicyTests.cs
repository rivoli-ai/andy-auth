using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Tests;

public sealed class SelfRegistrationPolicyTests
{
    [Fact]
    public void DefaultConfiguration_IsFailClosedAndRequiresConfirmedEmail()
    {
        using var factory = new CustomWebApplicationFactory();
        using var scope = factory.Services.CreateScope();

        scope.ServiceProvider
            .GetRequiredService<IOptions<SelfRegistrationOptions>>()
            .Value.Enabled.Should().BeFalse();
        scope.ServiceProvider
            .GetRequiredService<IOptions<IdentityOptions>>()
            .Value.SignIn.RequireConfirmedEmail.Should().BeTrue();
    }
}
