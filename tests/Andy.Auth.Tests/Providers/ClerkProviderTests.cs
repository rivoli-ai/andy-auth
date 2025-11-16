using Andy.Auth.Configuration;
using Andy.Auth.Providers;
using Andy.Auth.Tests.Helpers;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Tests.Providers;

public class ClerkProviderTests
{
    [Fact]
    public void Name_ShouldReturn_Clerk()
    {
        // Arrange
        var provider = new ClerkProvider();

        // Act
        var name = provider.Name;

        // Assert
        name.Should().Be("Clerk");
    }

    [Fact]
    public void ConfigureAuthentication_WithValidOptions_ShouldConfigureHandlers()
    {
        // Arrange
        var provider = new ClerkProvider();
        var services = new ServiceCollection();
        services.AddHttpClient(); // Required for Clerk opaque token handler
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            Clerk = new ClerkOptions
            {
                Domain = "test.clerk.accounts.dev"
            }
        };

        // Act
        provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var authOptions = serviceProvider.GetService<IAuthenticationSchemeProvider>();
        authOptions.Should().NotBeNull();
    }

    [Fact]
    public void ConfigureAuthentication_WithoutClerkConfig_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new ClerkProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            Clerk = null
        };

        // Act
        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Clerk configuration*");
    }

    [Fact]
    public void ConfigureAuthentication_WithoutDomain_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new ClerkProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            Clerk = new ClerkOptions
            {
                Domain = null
            }
        };

        // Act
        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Domain*");
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithValidPrincipal_ShouldExtractClaims()
    {
        // Arrange
        var provider = new ClerkProvider();
        var principal = TestClaimsPrincipalFactory.CreateClerkPrincipal(
            userId: "user_2abc123",
            email: "test@example.com",
            name: "Test User",
            picture: "https://example.com/avatar.jpg"
        );

        // Act
        var claims = await provider.GetUserClaimsAsync(principal);

        // Assert
        claims.Should().NotBeNull();
        claims.UserId.Should().Be("user_2abc123");
        claims.Email.Should().Be("test@example.com");
        claims.Name.Should().Be("Test User");
        claims.Picture.Should().Be("https://example.com/avatar.jpg");
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithoutUserId_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var provider = new ClerkProvider();
        var principal = new System.Security.Claims.ClaimsPrincipal();

        // Act
        Func<Task> act = async () => await provider.GetUserClaimsAsync(principal);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*User ID claim not found*");
    }

    [Fact]
    public void GetOAuthMetadata_WithValidOptions_ShouldReturnMetadata()
    {
        // Arrange
        var provider = new ClerkProvider();
        var domain = "test.clerk.accounts.dev";
        var options = new AndyAuthOptions
        {
            Clerk = new ClerkOptions
            {
                Domain = domain
            }
        };

        // Act
        var metadata = provider.GetOAuthMetadata(options);

        // Assert
        metadata.Should().NotBeNull();
        metadata.AuthorizationServer.ToString().Should().Be($"https://{domain}/");
        metadata.AuthorizationEndpoint.Should().NotBeNull();
        metadata.TokenEndpoint.Should().NotBeNull();
        metadata.RegistrationEndpoint.Should().BeNull(); // Clerk doesn't support DCR
        metadata.ScopesSupported.Should().Contain(new[] { "openid", "profile", "email" });
    }

    [Fact]
    public void GetOAuthMetadata_WithoutClerkConfig_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new ClerkProvider();
        var options = new AndyAuthOptions
        {
            Clerk = null
        };

        // Act
        Action act = () => provider.GetOAuthMetadata(options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Clerk configuration*");
    }
}
