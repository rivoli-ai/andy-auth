using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Seeds the database with initial data (clients, test users, etc.)
/// </summary>
public class DbSeeder
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DbSeeder> _logger;

    public DbSeeder(IServiceProvider serviceProvider, IConfiguration configuration, ILogger<DbSeeder> logger)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SeedAsync()
    {
        await SeedClientsAsync();
        await SeedTestUserAsync();
    }

    private async Task SeedClientsAsync()
    {
        var manager = _serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Lexipro API Client (for MCP)
        if (await manager.FindByClientIdAsync("lexipro-api") == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "lexipro-api",
                ClientSecret = "lexipro-secret-change-in-production",
                DisplayName = "Lexipro API",
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.Introspection,
                    OpenIddictConstants.Permissions.Endpoints.Revocation,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles,

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                },
                RedirectUris =
                {
                    new Uri("https://localhost:7001/callback"),
                    new Uri("https://lexipro-api-uat.rivoli.ai/callback"),
                    new Uri("https://lexipro-api.rivoli.ai/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:7001/"),
                    new Uri("https://lexipro-api-uat.rivoli.ai/"),
                    new Uri("https://lexipro-api.rivoli.ai/")
                }
            });

            _logger.LogInformation("Created OAuth client: lexipro-api");
        }

        // Wagram Web Client
        if (await manager.FindByClientIdAsync("wagram-web") == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "wagram-web",
                DisplayName = "Wagram Web Application",
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                // Public client - no secret
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles,

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                },
                RedirectUris =
                {
                    new Uri("https://localhost:4200/callback"),
                    new Uri("https://wagram-uat.vercel.app/callback"),
                    new Uri("https://wagram.ai/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:4200/"),
                    new Uri("https://wagram-uat.vercel.app/"),
                    new Uri("https://wagram.ai/")
                }
            });

            _logger.LogInformation("Created OAuth client: wagram-web");
        }

        // Claude Desktop Client (for MCP)
        if (await manager.FindByClientIdAsync("claude-desktop") == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "claude-desktop",
                DisplayName = "Claude Desktop",
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                // Public client - no secret
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                },
                RedirectUris =
                {
                    new Uri("http://127.0.0.1/callback"),
                    new Uri("http://localhost/callback")
                }
            });

            _logger.LogInformation("Created OAuth client: claude-desktop");
        }
    }

    private async Task SeedTestUserAsync()
    {
        var userManager = _serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        // Create test user only in development
        var isDevelopment = _configuration.GetValue<string>("ASPNETCORE_ENVIRONMENT") == "Development";
        if (!isDevelopment)
            return;

        const string testEmail = "test@andy.local";
        if (await userManager.FindByEmailAsync(testEmail) == null)
        {
            var testUser = new ApplicationUser
            {
                UserName = testEmail,
                Email = testEmail,
                EmailConfirmed = true,
                FullName = "Test User",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            var result = await userManager.CreateAsync(testUser, "Test123!");
            if (result.Succeeded)
            {
                _logger.LogInformation("Created test user: {Email} with password 'Test123!'", testEmail);
            }
            else
            {
                _logger.LogWarning("Failed to create test user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
    }
}
