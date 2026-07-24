using Andy.Auth.Configuration;
using Andy.Auth.Providers;
using Andy.Auth.Tests.Helpers;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Tests.Providers;

public class AndyAuthProviderTests
{
    [Fact]
    public void Name_ShouldReturn_AndyAuth()
    {
        // Arrange
        var provider = new AndyAuthProvider();

        // Act
        var name = provider.Name;

        // Assert
        name.Should().Be("AndyAuth");
    }

    [Fact]
    public void ConfigureAuthentication_WithValidOptions_ShouldConfigureJwtBearer()
    {
        // Arrange
        var provider = new AndyAuthProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            Authority = "https://auth.example.com",
            Audience = "test-api"
        };

        // Act
        provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var authOptions = serviceProvider.GetService<IAuthenticationSchemeProvider>();
        authOptions.Should().NotBeNull();
    }

    [Fact]
    public void ConfigureAuthentication_WithoutAuthority_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new AndyAuthProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            Authority = null,
            Audience = "test-api"
        };

        // Act
        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Authority*");
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithValidPrincipal_ShouldExtractClaims()
    {
        // Arrange
        var provider = new AndyAuthProvider();
        var principal = TestClaimsPrincipalFactory.CreateAndyAuthPrincipal(
            userId: "test-123",
            email: "test@example.com",
            name: "Test User"
        );

        // Act
        var claims = await provider.GetUserClaimsAsync(principal);

        // Assert
        claims.Should().NotBeNull();
        claims.UserId.Should().Be("test-123");
        claims.Email.Should().Be("test@example.com");
        claims.Name.Should().Be("Test User");
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithoutUserId_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var provider = new AndyAuthProvider();
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
        var provider = new AndyAuthProvider();
        var options = new AndyAuthOptions
        {
            Authority = "https://auth.example.com"
        };

        // Act
        var metadata = provider.GetOAuthMetadata(options);

        // Assert
        metadata.Should().NotBeNull();
        metadata.AuthorizationServer.ToString().Should().Be("https://auth.example.com/");
        metadata.AuthorizationEndpoint.Should().NotBeNull();
        metadata.TokenEndpoint.Should().NotBeNull();
        metadata.RegistrationEndpoint.Should().NotBeNull();
        metadata.ScopesSupported.Should().Contain(new[] { "openid", "profile", "email" });
    }

    [Fact]
    public void GetOAuthMetadata_WithoutAuthority_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new AndyAuthProvider();
        var options = new AndyAuthOptions
        {
            Authority = null
        };

        // Act
        Action act = () => provider.GetOAuthMetadata(options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Authority*");
    }

    // ==================== andy-auth#148 ====================

    [Fact]
    public void ConfigureAuthentication_WithoutAudience_ShouldThrow()
    {
        // Previously this silently set ValidateAudience = false, so the
        // consumer accepted every token the authority ever minted — including
        // tokens issued for a different API on the same IdP.
        var provider = new AndyAuthProvider();
        var services = new ServiceCollection();
        var authBuilder = new AuthenticationBuilder(services);
        var options = new AndyAuthOptions
        {
            Authority = "https://auth.example.com",
            Audience = null,
            ValidAudiences = null
        };

        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        act.Should().Throw<ArgumentException>().WithMessage("*Audience*");
    }

    [Fact]
    public void ConfigureAuthentication_WithOnlyValidAudiences_ShouldSucceed()
    {
        // ValidAudiences alone is a legitimate configuration — an API that
        // accepts several audience values but names none of them "primary".
        var provider = new AndyAuthProvider();
        var services = new ServiceCollection();
        var authBuilder = new AuthenticationBuilder(services);
        var options = new AndyAuthOptions
        {
            Authority = "https://auth.example.com",
            Audience = null,
            ValidAudiences = new[] { "urn:andy-docs-api", "https://localhost:5101/mcp" }
        };

        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        act.Should().NotThrow();
    }

    [Fact]
    public void ConfigureAuthentication_WithEmptyValidAudiences_ShouldThrow()
    {
        // An array of blanks is no audience at all.
        var provider = new AndyAuthProvider();
        var services = new ServiceCollection();
        var authBuilder = new AuthenticationBuilder(services);
        var options = new AndyAuthOptions
        {
            Authority = "https://auth.example.com",
            Audience = null,
            ValidAudiences = new[] { "", null! }
        };

        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        act.Should().Throw<ArgumentException>().WithMessage("*Audience*");
    }

    [Fact]
    public void ConfigureAuthentication_AllowingInvalidCertificates_ShouldThrowInProduction()
    {
        var provider = new AndyAuthProvider();
        var services = new ServiceCollection();
        var authBuilder = new AuthenticationBuilder(services);
        var options = new AndyAuthOptions
        {
            Authority = "https://auth.example.com",
            Audience = "test-api",
            AllowInvalidBackchannelCertificates = true
        };

        var previous = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var previousDotnet = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
        try
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
            Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", null);

            Action act = () => provider.ConfigureAuthentication(authBuilder, options);

            act.Should().Throw<InvalidOperationException>()
                .WithMessage("*AllowInvalidBackchannelCertificates*");
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", previous);
            Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", previousDotnet);
        }
    }

    [Fact]
    public void GetOAuthMetadata_WithPathPrefixedAuthority_ShouldPreservePrefix()
    {
        // Conductor's unified proxy exposes this server under /auth. A rooted
        // path discarded the prefix and every endpoint came back wrong.
        var provider = new AndyAuthProvider();
        var options = new AndyAuthOptions { Authority = "http://localhost:9100/auth/" };

        var metadata = provider.GetOAuthMetadata(options);

        metadata.AuthorizationEndpoint.ToString().Should().Be("http://localhost:9100/auth/connect/authorize");
        metadata.TokenEndpoint.ToString().Should().Be("http://localhost:9100/auth/connect/token");
        metadata.RegistrationEndpoint.ToString().Should().Be("http://localhost:9100/auth/connect/register");
    }

    [Fact]
    public void GetOAuthMetadata_WithPathPrefixAndNoTrailingSlash_ShouldPreservePrefix()
    {
        // Uri resolution drops the last segment of a base without a trailing
        // slash, so "/auth" would otherwise lose the prefix too.
        var provider = new AndyAuthProvider();
        var options = new AndyAuthOptions { Authority = "http://localhost:9100/auth" };

        var metadata = provider.GetOAuthMetadata(options);

        metadata.AuthorizationEndpoint.ToString().Should().Be("http://localhost:9100/auth/connect/authorize");
    }
}
