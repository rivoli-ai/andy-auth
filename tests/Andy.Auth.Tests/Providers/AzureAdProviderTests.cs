using Andy.Auth.Configuration;
using Andy.Auth.Providers;
using Andy.Auth.Tests.Helpers;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Tests.Providers;

public class AzureAdProviderTests
{
    [Fact]
    public void Name_ShouldReturn_AzureAD()
    {
        // Arrange
        var provider = new AzureAdProvider();

        // Act
        var name = provider.Name;

        // Assert
        name.Should().Be("AzureAD");
    }

    [Fact]
    public void ConfigureAuthentication_WithValidOptions_ShouldConfigureJwtBearer()
    {
        // Arrange
        var provider = new AzureAdProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            AzureAd = new AzureAdOptions
            {
                TenantId = "12345678-1234-1234-1234-123456789012",
                ClientId = "app-client-id"
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
    public void ConfigureAuthentication_WithoutAzureAdConfig_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new AzureAdProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            AzureAd = null
        };

        // Act
        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*AzureAd configuration*");
    }

    [Fact]
    public void ConfigureAuthentication_WithoutTenantId_ShouldThrowArgumentException()
    {
        // Arrange
        var provider = new AzureAdProvider();
        var services = new ServiceCollection();
        var authBuilder = services.AddAuthentication();
        var options = new AndyAuthOptions
        {
            AzureAd = new AzureAdOptions
            {
                TenantId = null,
                ClientId = "app-client-id"
            }
        };

        // Act
        Action act = () => provider.ConfigureAuthentication(authBuilder, options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*TenantId*");
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithValidPrincipal_ShouldExtractAzureAdClaims()
    {
        // Arrange
        var provider = new AzureAdProvider();
        var objectId = "12345678-1234-1234-1234-123456789012";
        var tenantId = "87654321-4321-4321-4321-210987654321";
        var principal = TestClaimsPrincipalFactory.CreateAzureAdPrincipal(
            objectId: objectId,
            upn: "test@contoso.com",
            name: "Test User",
            tenantId: tenantId
        );

        // Act
        var claims = await provider.GetUserClaimsAsync(principal);

        // Assert
        claims.Should().NotBeNull();
        claims.UserId.Should().Be(objectId);
        claims.Email.Should().Be("test@contoso.com");
        claims.Name.Should().Be("Test User");
        claims.AdditionalClaims.Should().ContainKey("tenant_id");
        claims.AdditionalClaims!["tenant_id"].Should().Be(tenantId);
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithoutObjectId_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var provider = new AzureAdProvider();
        var principal = new System.Security.Claims.ClaimsPrincipal();

        // Act
        Func<Task> act = async () => await provider.GetUserClaimsAsync(principal);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*oid*");
    }

    [Fact]
    public void GetOAuthMetadata_WithValidOptions_ShouldReturnMetadata()
    {
        // Arrange
        var provider = new AzureAdProvider();
        var tenantId = "12345678-1234-1234-1234-123456789012";
        var options = new AndyAuthOptions
        {
            AzureAd = new AzureAdOptions
            {
                TenantId = tenantId,
                ClientId = "app-client-id"
            }
        };

        // Act
        var metadata = provider.GetOAuthMetadata(options);

        // Assert
        metadata.Should().NotBeNull();
        metadata.AuthorizationServer.ToString().Should().Contain(tenantId);
        metadata.AuthorizationEndpoint.Should().NotBeNull();
        metadata.TokenEndpoint.Should().NotBeNull();
        metadata.RegistrationEndpoint.Should().BeNull(); // Azure AD doesn't support DCR
        metadata.ScopesSupported.Should().Contain(new[] { "openid", "profile", "email", "offline_access" });
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com/")]
    [InlineData("https://login.microsoftonline.us/")]
    public void GetOAuthMetadata_WithCustomInstance_ShouldUseCorrectAuthority(string instance)
    {
        // Arrange
        var provider = new AzureAdProvider();
        var tenantId = "12345678-1234-1234-1234-123456789012";
        var options = new AndyAuthOptions
        {
            AzureAd = new AzureAdOptions
            {
                TenantId = tenantId,
                ClientId = "app-client-id",
                Instance = instance
            }
        };

        // Act
        var metadata = provider.GetOAuthMetadata(options);

        // Assert
        metadata.AuthorizationServer.ToString().Should().StartWith(instance.TrimEnd('/'));
    }
}
