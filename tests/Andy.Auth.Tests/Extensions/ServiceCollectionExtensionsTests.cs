using Andy.Auth.Configuration;
using Andy.Auth.Extensions;
using Andy.Auth.Providers;
using Andy.Auth.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Tests.Extensions;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAndyAuth_WithAndyAuthProvider_ShouldRegisterServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = AuthProvider.AndyAuth,
            Authority = "https://auth.example.com",
            Audience = "test-api"
        };

        // Act
        services.AddAndyAuth(options);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var authProvider = serviceProvider.GetService<IAuthProvider>();
        authProvider.Should().NotBeNull();
        authProvider.Should().BeOfType<AndyAuthProvider>();

        var currentUserService = serviceProvider.GetService<ICurrentUserService>();
        currentUserService.Should().NotBeNull();

        var authSchemeProvider = serviceProvider.GetService<IAuthenticationSchemeProvider>();
        authSchemeProvider.Should().NotBeNull();
    }

    [Fact]
    public void AddAndyAuth_WithAzureAdProvider_ShouldRegisterServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = AuthProvider.AzureAD,
            AzureAd = new AzureAdOptions
            {
                TenantId = "12345678-1234-1234-1234-123456789012",
                ClientId = "app-client-id"
            }
        };

        // Act
        services.AddAndyAuth(options);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var authProvider = serviceProvider.GetService<IAuthProvider>();
        authProvider.Should().NotBeNull();
        authProvider.Should().BeOfType<AzureAdProvider>();
    }

    [Fact]
    public void AddAndyAuth_WithClerkProvider_ShouldRegisterServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = AuthProvider.Clerk,
            Clerk = new ClerkOptions
            {
                Domain = "test.clerk.accounts.dev"
            }
        };

        // Act
        services.AddAndyAuth(options);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var authProvider = serviceProvider.GetService<IAuthProvider>();
        authProvider.Should().NotBeNull();
        authProvider.Should().BeOfType<ClerkProvider>();
    }

    [Fact]
    public void AddAndyAuth_WithConfiguration_ShouldBindOptions()
    {
        // Arrange
        var configData = new Dictionary<string, string?>
        {
            ["AndyAuth:Provider"] = "AndyAuth",
            ["AndyAuth:Authority"] = "https://auth.example.com",
            ["AndyAuth:Audience"] = "test-api"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        var services = new ServiceCollection();

        // Act
        services.AddAndyAuth(configuration);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var andyAuthOptions = serviceProvider.GetService<AndyAuthOptions>();
        andyAuthOptions.Should().NotBeNull();
        andyAuthOptions!.Provider.Should().Be(AuthProvider.AndyAuth);
        andyAuthOptions.Authority.Should().Be("https://auth.example.com");
        andyAuthOptions.Audience.Should().Be("test-api");
    }

    [Fact]
    public void AddAndyAuth_WithAction_ShouldConfigureOptions()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddAndyAuth(options =>
        {
            options.Provider = AuthProvider.AndyAuth;
            options.Authority = "https://auth.example.com";
            options.Audience = "test-api";
        });

        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var andyAuthOptions = serviceProvider.GetService<AndyAuthOptions>();
        andyAuthOptions.Should().NotBeNull();
        andyAuthOptions!.Provider.Should().Be(AuthProvider.AndyAuth);
        andyAuthOptions.Authority.Should().Be("https://auth.example.com");
    }

    [Fact]
    public void AddAndyAuth_ShouldRegisterHttpContextAccessor()
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = AuthProvider.AndyAuth,
            Authority = "https://auth.example.com"
        };

        // Act
        services.AddAndyAuth(options);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var httpContextAccessor = serviceProvider.GetService<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        httpContextAccessor.Should().NotBeNull();
    }

    [Fact]
    public void AddAndyAuth_ShouldRegisterHttpClientForClerk()
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = AuthProvider.Clerk,
            Clerk = new ClerkOptions
            {
                Domain = "test.clerk.accounts.dev"
            }
        };

        // Act
        services.AddAndyAuth(options);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
        httpClientFactory.Should().NotBeNull();
    }

    [Fact]
    public void AddAndyAuth_WithCustomProvider_ShouldThrowNotImplementedException()
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = AuthProvider.Custom
        };

        // Act
        Action act = () => services.AddAndyAuth(options);

        // Assert
        act.Should().Throw<NotImplementedException>()
            .WithMessage("*Custom provider not implemented*");
    }

    [Theory]
    [InlineData(AuthProvider.AndyAuth)]
    [InlineData(AuthProvider.AzureAD)]
    [InlineData(AuthProvider.Clerk)]
    public void AddAndyAuth_ShouldRegisterAuthorizationServices(AuthProvider provider)
    {
        // Arrange
        var services = new ServiceCollection();
        var options = new AndyAuthOptions
        {
            Provider = provider,
            Authority = "https://auth.example.com",
            AzureAd = new AzureAdOptions
            {
                TenantId = "test-tenant",
                ClientId = "test-client"
            },
            Clerk = new ClerkOptions
            {
                Domain = "test.clerk.accounts.dev"
            }
        };

        // Act
        services.AddAndyAuth(options);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var authorizationService = serviceProvider.GetService<Microsoft.AspNetCore.Authorization.IAuthorizationService>();
        authorizationService.Should().NotBeNull();
    }
}
