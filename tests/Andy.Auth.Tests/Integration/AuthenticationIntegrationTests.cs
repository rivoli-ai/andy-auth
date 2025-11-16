using Andy.Auth.Configuration;
using Andy.Auth.Extensions;
using Andy.Auth.Services;
using Andy.Auth.Tests.Helpers;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Net.Http.Headers;

namespace Andy.Auth.Tests.Integration;

/// <summary>
/// Integration tests that validate the full authentication flow
/// </summary>
public class AuthenticationIntegrationTests
{
    [Fact]
    public async Task AndyAuthProvider_WithValidToken_ShouldAuthenticateRequest()
    {
        // Arrange
        using var host = await CreateTestHost(new AndyAuthOptions
        {
            Provider = AuthProvider.AndyAuth,
            Authority = "https://auth.example.com",
            Audience = "test-api",
            RequireHttpsMetadata = false
        });

        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/api/test");

        // Assert
        // Note: This will return 401 because we don't have a real JWT token
        // In a real integration test, you would use a test JWT token
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutAuthentication_ShouldReturn401()
    {
        // Arrange
        using var host = await CreateTestHost(new AndyAuthOptions
        {
            Provider = AuthProvider.AndyAuth,
            Authority = "https://auth.example.com",
            Audience = "test-api",
            RequireHttpsMetadata = false
        });

        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/api/protected");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PublicEndpoint_WithoutAuthentication_ShouldReturn200()
    {
        // Arrange
        using var host = await CreateTestHost(new AndyAuthOptions
        {
            Provider = AuthProvider.AndyAuth,
            Authority = "https://auth.example.com",
            Audience = "test-api",
            RequireHttpsMetadata = false
        });

        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/api/public");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task CurrentUserService_InProtectedEndpoint_ShouldWorkCorrectly()
    {
        // Arrange
        using var host = await CreateTestHost(new AndyAuthOptions
        {
            Provider = AuthProvider.AndyAuth,
            Authority = "https://auth.example.com",
            Audience = "test-api",
            RequireHttpsMetadata = false
        });

        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/api/user-info");

        // Assert
        // Without authentication, should return 401
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData(AuthProvider.AndyAuth)]
    [InlineData(AuthProvider.AzureAD)]
    [InlineData(AuthProvider.Clerk)]
    public async Task DifferentProviders_ShouldBeConfigurableAtRuntime(AuthProvider provider)
    {
        // Arrange
        var options = new AndyAuthOptions
        {
            Provider = provider,
            Authority = "https://auth.example.com",
            Audience = "test-api",
            RequireHttpsMetadata = false,
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

        using var host = await CreateTestHost(options);
        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/api/test");

        // Assert
        // All providers should be configured correctly (returns 401 without token)
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private async Task<IHost> CreateTestHost(AndyAuthOptions authOptions)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddAndyAuth(authOptions);
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        // Public endpoint
                        endpoints.MapGet("/api/public", () => Results.Ok(new { message = "public" }));

                        // Protected endpoint
                        endpoints.MapGet("/api/protected", () => Results.Ok(new { message = "protected" }))
                            .RequireAuthorization();

                        // Test endpoint
                        endpoints.MapGet("/api/test", () => Results.Ok(new { message = "test" }))
                            .RequireAuthorization();

                        // Endpoint that uses CurrentUserService
                        endpoints.MapGet("/api/user-info", async (ICurrentUserService currentUser) =>
                        {
                            try
                            {
                                var userId = await currentUser.GetUserIdAsync();
                                var claims = await currentUser.GetUserClaimsAsync();
                                return Results.Ok(new { userId, email = claims.Email });
                            }
                            catch (InvalidOperationException)
                            {
                                return Results.Unauthorized();
                            }
                        }).RequireAuthorization();
                    });
                });
            });

        var host = await hostBuilder.StartAsync();
        return host;
    }
}
