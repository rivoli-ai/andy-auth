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
        // Delete existing client if it exists (to ensure clean slate with updated permissions)
        var lexiproApiClient = await manager.FindByClientIdAsync("lexipro-api");
        if (lexiproApiClient != null)
        {
            await manager.DeleteAsync(lexiproApiClient);
            _logger.LogInformation("Deleted existing OAuth client: lexipro-api");
        }

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
                "scp:urn:lexipro-api",  // Permission to request lexipro-api resource

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

        _logger.LogInformation("Created OAuth client: lexipro-api with updated permissions");

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

                // Allow requesting resource servers (for MCP) - using rst: prefix for OpenIddict 7.x resource parameter
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5154/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5154/mcp"
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

        // ChatGPT Client (for MCP)
        var chatGptClient = await manager.FindByClientIdAsync("chatgpt");
        if (chatGptClient != null)
        {
            await manager.DeleteAsync(chatGptClient);
            _logger.LogInformation("Deleted existing OAuth client: chatgpt");
        }

        var chatGptDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "chatgpt",
            DisplayName = "ChatGPT",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                "scp:urn:lexipro-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp"
            },
            RedirectUris =
            {
                // ChatGPT OAuth callback URLs
                new Uri("https://chat.openai.com/api/mcp/auth_callback"),
                new Uri("https://chatgpt.com/api/mcp/auth_callback"),
                // Local development
                new Uri("http://127.0.0.1/callback"),
                new Uri("http://localhost/callback")
            }
        };

        await manager.CreateAsync(chatGptDescriptor);
        _logger.LogInformation("Created OAuth client: chatgpt");

        // Cline (VS Code Extension - formerly Claude Dev)
        var clineClient = await manager.FindByClientIdAsync("cline");
        if (clineClient != null)
        {
            await manager.DeleteAsync(clineClient);
            _logger.LogInformation("Deleted existing OAuth client: cline");
        }

        var clineDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "cline",
            DisplayName = "Cline (VS Code)",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                "scp:urn:lexipro-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5154/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5154/mcp"
            },
            RedirectUris =
            {
                // VS Code extension localhost callbacks (various ports)
                new Uri("http://127.0.0.1/callback"),
                new Uri("http://127.0.0.1:3000/callback"),
                new Uri("http://127.0.0.1:8080/callback"),
                new Uri("http://localhost/callback"),
                new Uri("http://localhost:3000/callback"),
                new Uri("http://localhost:8080/callback"),
                // VS Code protocol handler
                new Uri("vscode://saoudrizwan.claude-dev/callback")
            }
        };

        await manager.CreateAsync(clineDescriptor);
        _logger.LogInformation("Created OAuth client: cline");

        // Roo (VS Code Extension for Claude)
        var rooClient = await manager.FindByClientIdAsync("roo");
        if (rooClient != null)
        {
            await manager.DeleteAsync(rooClient);
            _logger.LogInformation("Deleted existing OAuth client: roo");
        }

        var rooDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "roo",
            DisplayName = "Roo (VS Code)",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                "scp:urn:lexipro-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5154/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5154/mcp"
            },
            RedirectUris =
            {
                // VS Code extension localhost callbacks
                new Uri("http://127.0.0.1/callback"),
                new Uri("http://127.0.0.1:3000/callback"),
                new Uri("http://127.0.0.1:8080/callback"),
                new Uri("http://localhost/callback"),
                new Uri("http://localhost:3000/callback"),
                new Uri("http://localhost:8080/callback"),
                // VS Code protocol handler (adjust extension ID as needed)
                new Uri("vscode://roo-cline.roo-cline/callback")
            }
        };

        await manager.CreateAsync(rooDescriptor);
        _logger.LogInformation("Created OAuth client: roo");

        // Continue.dev (VS Code/IntelliJ Extension)
        var continueClient = await manager.FindByClientIdAsync("continue-dev");
        if (continueClient != null)
        {
            await manager.DeleteAsync(continueClient);
            _logger.LogInformation("Deleted existing OAuth client: continue-dev");
        }

        var continueDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "continue-dev",
            DisplayName = "Continue.dev",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                "scp:urn:lexipro-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://lexipro-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5154/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5154/mcp"
            },
            RedirectUris =
            {
                // VS Code/IntelliJ extension localhost callbacks
                new Uri("http://127.0.0.1/callback"),
                new Uri("http://127.0.0.1:3000/callback"),
                new Uri("http://127.0.0.1:8080/callback"),
                new Uri("http://localhost/callback"),
                new Uri("http://localhost:3000/callback"),
                new Uri("http://localhost:8080/callback"),
                // VS Code protocol handler
                new Uri("vscode://continue.continue/callback")
            }
        };

        await manager.CreateAsync(continueDescriptor);
        _logger.LogInformation("Created OAuth client: continue-dev");
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

        // Create test user in non-production environments (Development, UAT, Staging)
        var environment = _configuration.GetValue<string>("ASPNETCORE_ENVIRONMENT") ??
                          Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";
        var isNonProduction = environment != "Production";

        if (isNonProduction)
        {
            const string testEmail = "test@andy.local";
            var existingTestUser = await userManager.FindByEmailAsync(testEmail);

            if (existingTestUser == null)
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
                    _logger.LogInformation("Created test user: {Email} with password 'Test123!' in {Environment} environment", testEmail, environment);
                }
                else
                {
                    _logger.LogWarning("Failed to create test user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                // Reset password for existing test user to ensure it's always Test123!
                var token = await userManager.GeneratePasswordResetTokenAsync(existingTestUser);
                var resetResult = await userManager.ResetPasswordAsync(existingTestUser, token, "Test123!");
                if (resetResult.Succeeded)
                {
                    _logger.LogInformation("Reset password for test user: {Email}", testEmail);
                }

                // Clear any lockout
                if (existingTestUser.AccessFailedCount > 0 || existingTestUser.LockoutEnd != null)
                {
                    existingTestUser.AccessFailedCount = 0;
                    existingTestUser.LockoutEnd = null;
                    await userManager.UpdateAsync(existingTestUser);
                    _logger.LogInformation("Cleared lockout for test user: {Email}", testEmail);
                }
            }
        }
    }
}
