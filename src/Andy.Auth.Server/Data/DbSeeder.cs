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
        await SeedRolesAsync();
        await SeedScopesAsync();
        await SeedClientsAsync();
        await SeedTestUserAsync();
    }

    private async Task SeedRolesAsync()
    {
        var roleManager = _serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Create Admin role
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
            _logger.LogInformation("Created role: Admin");
        }

        // Create User role (default for all users)
        if (!await roleManager.RoleExistsAsync("User"))
        {
            await roleManager.CreateAsync(new IdentityRole("User"));
            _logger.LogInformation("Created role: User");
        }
    }

    private async Task SeedScopesAsync()
    {
        var manager = _serviceProvider.GetRequiredService<IOpenIddictScopeManager>();

        // Register the lexipro-api resource scope
        if (await manager.FindByNameAsync("urn:lexipro-api") == null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "urn:lexipro-api",
                DisplayName = "Lexipro API",
                Resources =
                {
                    "urn:lexipro-api"
                }
            });

            _logger.LogInformation("Created API resource scope: urn:lexipro-api");
        }
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
        var wagramClient = await manager.FindByClientIdAsync("wagram-web");
        if (wagramClient == null)
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
                    "scp:urn:lexipro-api",  // Permission to request lexipro-api resource

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                },
                RedirectUris =
                {
                    new Uri("https://localhost:4200/callback"),
                    new Uri("https://wagram-uat.vercel.app/callback"),
                    new Uri("https://wargram-ai-uat.vercel.app/callback"),
                    new Uri("https://wagram.ai/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:4200/"),
                    new Uri("https://wagram-uat.vercel.app/"),
                    new Uri("https://wargram-ai-uat.vercel.app/"),
                    new Uri("https://wagram.ai/")
                }
            });

            _logger.LogInformation("Created OAuth client: wagram-web");
        }
        else
        {
            // Update existing client to add permission for urn:lexipro-api resource
            var descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, wagramClient);

            const string lexiproPermission = "scp:urn:lexipro-api";
            if (!descriptor.Permissions.Contains(lexiproPermission))
            {
                descriptor.Permissions.Add(lexiproPermission);
                await manager.UpdateAsync(wagramClient, descriptor);
                _logger.LogInformation("Updated OAuth client: wagram-web - added urn:lexipro-api permission");
            }
        }

        // Claude Desktop Client (for MCP)
        // Delete existing client if it exists (to ensure clean slate)
        var claudeDesktopClient = await manager.FindByClientIdAsync("claude-desktop");
        if (claudeDesktopClient != null)
        {
            await manager.DeleteAsync(claudeDesktopClient);
            _logger.LogInformation("Deleted existing OAuth client: claude-desktop");
        }

        // Create claude-desktop client with correct redirect URIs
        var claudeDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "claude-desktop",
            DisplayName = "Claude Desktop",
            ClientType = OpenIddictConstants.ClientTypes.Public, // Public client - no secret
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                "scp:urn:lexipro-api",  // Permission to request lexipro-api resource

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.ResourceServer + "https://lexipro-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.ResourceServer + "https://lexipro-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.ResourceServer + "https://localhost:7001/mcp",
                OpenIddictConstants.Permissions.Prefixes.ResourceServer + "https://localhost:5154/mcp",
                OpenIddictConstants.Permissions.Prefixes.ResourceServer + "http://localhost:5154/mcp"
            },
            RedirectUris =
            {
                // Claude.ai MCP OAuth callback (current)
                new Uri("https://claude.ai/api/mcp/auth_callback"),
                // Claude.com MCP OAuth callback (future)
                new Uri("https://claude.com/api/mcp/auth_callback"),
                // Local development callbacks
                new Uri("http://127.0.0.1/callback"),
                new Uri("http://localhost/callback")
            }
        };

        await manager.CreateAsync(claudeDescriptor);
        _logger.LogInformation("Created OAuth client: claude-desktop with correct redirect URIs and resource permissions");
    }

    private async Task SeedTestUserAsync()
    {
        var userManager = _serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        // Create admin users (sam@rivoli.ai, ty@rivoli.ai, and admin@andy-auth.local)
        var adminUsers = new[]
        {
            new { Email = "sam@rivoli.ai", FullName = "Sam Ben Grine", Password = "REDACTED_ADMIN_PASSWORD" },
            new { Email = "ty@rivoli.ai", FullName = "Ty Morrow", Password = "wonpic-bopjev-nuRgo2" },
            new { Email = "admin@andy-auth.local", FullName = "System Administrator", Password = "Admin123!ChangeMe" }
        };

        foreach (var userInfo in adminUsers)
        {
            var existingUser = await userManager.FindByEmailAsync(userInfo.Email);
            if (existingUser == null)
            {
                var adminUser = new ApplicationUser
                {
                    UserName = userInfo.Email,
                    Email = userInfo.Email,
                    EmailConfirmed = true,
                    FullName = userInfo.FullName,
                    IsActive = true,
                    IsSystemUser = true, // Protected from deletion
                    CreatedAt = DateTime.UtcNow
                };

                var result = await userManager.CreateAsync(adminUser, userInfo.Password);
                if (result.Succeeded)
                {
                    // Assign Admin role
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    _logger.LogInformation("Created system admin user: {Email} with Admin role", userInfo.Email);
                }
                else
                {
                    _logger.LogWarning("Failed to create admin user {Email}: {Errors}",
                        userInfo.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                // Ensure existing user has Admin role and IsSystemUser flag
                bool needsUpdate = false;

                if (!await userManager.IsInRoleAsync(existingUser, "Admin"))
                {
                    await userManager.AddToRoleAsync(existingUser, "Admin");
                    _logger.LogInformation("Added Admin role to existing user: {Email}", userInfo.Email);
                }

                if (!existingUser.IsSystemUser)
                {
                    existingUser.IsSystemUser = true;
                    needsUpdate = true;
                    _logger.LogInformation("Marked user as system user: {Email}", userInfo.Email);
                }

                // Clear any lockout for system users
                if (existingUser.AccessFailedCount > 0 || existingUser.LockoutEnd != null)
                {
                    existingUser.AccessFailedCount = 0;
                    existingUser.LockoutEnd = null;
                    needsUpdate = true;
                    _logger.LogInformation("Cleared lockout for system user: {Email}", userInfo.Email);
                }

                // Reset password for system users to ensure it matches the expected password
                var passwordResetToken = await userManager.GeneratePasswordResetTokenAsync(existingUser);
                var passwordResetResult = await userManager.ResetPasswordAsync(existingUser, passwordResetToken, userInfo.Password);
                if (passwordResetResult.Succeeded)
                {
                    _logger.LogInformation("Reset password for system user: {Email}", userInfo.Email);
                }
                else
                {
                    _logger.LogWarning("Failed to reset password for system user {Email}: {Errors}",
                        userInfo.Email, string.Join(", ", passwordResetResult.Errors.Select(e => e.Description)));
                }

                if (needsUpdate)
                {
                    await userManager.UpdateAsync(existingUser);
                }
            }
        }

        // Create test user only in development
        var isDevelopment = _configuration.GetValue<string>("ASPNETCORE_ENVIRONMENT") == "Development";
        if (isDevelopment)
        {
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
                    // Assign User role to test user (not Admin)
                    await userManager.AddToRoleAsync(testUser, "User");
                    _logger.LogInformation("Created test user: {Email} with password 'Test123!'", testEmail);
                }
                else
                {
                    _logger.LogWarning("Failed to create test user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
    }
}
