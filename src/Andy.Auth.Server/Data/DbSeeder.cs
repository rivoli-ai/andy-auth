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

        // Register the andy-docs-api resource scope
        if (await manager.FindByNameAsync("urn:andy-docs-api") == null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "urn:andy-docs-api",
                DisplayName = "Andy Docs API",
                Resources =
                {
                    "urn:andy-docs-api"
                }
            });

            _logger.LogInformation("Created API resource scope: urn:andy-docs-api");
        }
    }

    private async Task SeedClientsAsync()
    {
        var manager = _serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Andy Docs API Client (for MCP)
        // Delete existing client if it exists (to ensure clean slate with updated permissions)
        var andyDocsApiClient = await manager.FindByClientIdAsync("andy-docs-api");
        if (andyDocsApiClient != null)
        {
            await manager.DeleteAsync(andyDocsApiClient);
            _logger.LogInformation("Deleted existing OAuth client: andy-docs-api");
        }

        // Also clean up legacy lexipro-api client if it exists
        var legacyClient = await manager.FindByClientIdAsync("lexipro-api");
        if (legacyClient != null)
        {
            await manager.DeleteAsync(legacyClient);
            _logger.LogInformation("Deleted legacy OAuth client: lexipro-api");
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "andy-docs-api",
            ClientSecret = "andy-docs-secret-change-in-production",
            DisplayName = "Andy Docs API",
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
                "scp:urn:andy-docs-api",  // Permission to request andy-docs-api resource

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris =
            {
                new Uri("https://localhost:7001/callback"),
                new Uri("https://andy-docs-uat.up.railway.app/callback"),
                new Uri("https://andy-docs-api.rivoli.ai/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:7001/"),
                new Uri("https://andy-docs-uat.up.railway.app/"),
                new Uri("https://andy-docs-api.rivoli.ai/")
            }
        });

        _logger.LogInformation("Created OAuth client: andy-docs-api with updated permissions");

        // Wagram Web Client
        // Delete and recreate to ensure latest configuration
        var wagramClient = await manager.FindByClientIdAsync("wagram-web");
        if (wagramClient != null)
        {
            await manager.DeleteAsync(wagramClient);
            _logger.LogInformation("Deleted existing OAuth client: wagram-web");
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "wagram-web",
            DisplayName = "Wagram Web Application",
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
                OpenIddictConstants.Permissions.Scopes.Roles,
                "scp:urn:andy-docs-api",  // Permission to request andy-docs-api resource

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

        _logger.LogInformation("Created OAuth client: wagram-web with updated redirect URIs");

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
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",  // Permission to request andy-docs-api resource

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP) - using rst: prefix for OpenIddict 7.x resource parameter
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
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
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
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
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
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
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
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

        // Kilocode (VS Code Extension - fork of Cline/Roo)
        var kilocodeClient = await manager.FindByClientIdAsync("kilocode");
        if (kilocodeClient != null)
        {
            await manager.DeleteAsync(kilocodeClient);
            _logger.LogInformation("Deleted existing OAuth client: kilocode");
        }

        var kilocodeDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "kilocode",
            DisplayName = "Kilocode (VS Code)",
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
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
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
                new Uri("vscode://kilocode.kilo-code/callback")
            }
        };

        await manager.CreateAsync(kilocodeDescriptor);
        _logger.LogInformation("Created OAuth client: kilocode");

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
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
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

    /// <summary>
    /// Generates a random password that meets ASP.NET Identity requirements
    /// </summary>
    private static string GenerateRandomPassword()
    {
        const string upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowerCase = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string special = "!@#$%^&*";

        var random = new Random();
        var password = new char[16];

        // Ensure at least one of each required character type
        password[0] = upperCase[random.Next(upperCase.Length)];
        password[1] = lowerCase[random.Next(lowerCase.Length)];
        password[2] = digits[random.Next(digits.Length)];
        password[3] = special[random.Next(special.Length)];

        // Fill the rest with random characters from all types
        var allChars = upperCase + lowerCase + digits + special;
        for (int i = 4; i < password.Length; i++)
        {
            password[i] = allChars[random.Next(allChars.Length)];
        }

        // Shuffle the password
        for (int i = password.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            (password[i], password[j]) = (password[j], password[i]);
        }

        return new string(password);
    }

    private async Task SeedTestUserAsync()
    {
        var userManager = _serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        // Admin user configuration
        // Passwords are read from environment variables for security
        // Set these in your environment or Railway variables:
        //   ADMIN_PASSWORD_SAM - Password for sam@rivoli.ai
        //   ADMIN_PASSWORD_TY - Password for ty@rivoli.ai
        //   ADMIN_PASSWORD_DEFAULT - Password for admin@andy-auth.local
        var adminUsers = new[]
        {
            new {
                Email = "sam@rivoli.ai",
                FullName = "Sam Ben Grine",
                PasswordEnvVar = "ADMIN_PASSWORD_SAM",
                DefaultPassword = GenerateRandomPassword() // Only used if env var not set
            },
            new {
                Email = "ty@rivoli.ai",
                FullName = "Ty Morrow",
                PasswordEnvVar = "ADMIN_PASSWORD_TY",
                DefaultPassword = GenerateRandomPassword()
            },
            new {
                Email = "admin@andy-auth.local",
                FullName = "System Administrator",
                PasswordEnvVar = "ADMIN_PASSWORD_DEFAULT",
                DefaultPassword = GenerateRandomPassword()
            }
        };

        foreach (var userInfo in adminUsers)
        {
            var existingUser = await userManager.FindByEmailAsync(userInfo.Email);
            if (existingUser == null)
            {
                // Get password from environment variable, or use generated default
                var password = Environment.GetEnvironmentVariable(userInfo.PasswordEnvVar);
                var usingEnvVar = !string.IsNullOrEmpty(password);

                if (!usingEnvVar)
                {
                    password = userInfo.DefaultPassword;
                    _logger.LogWarning(
                        "No password set for {Email} via {EnvVar}. Using generated password: {Password}. " +
                        "Set the environment variable to use a specific password.",
                        userInfo.Email, userInfo.PasswordEnvVar, password);
                }

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

                var result = await userManager.CreateAsync(adminUser, password);
                if (result.Succeeded)
                {
                    // Assign Admin role
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    _logger.LogInformation(
                        "Created system admin user: {Email} with Admin role (password from {Source})",
                        userInfo.Email,
                        usingEnvVar ? "environment variable" : "generated default");
                }
                else
                {
                    _logger.LogWarning("Failed to create admin user {Email}: {Errors}",
                        userInfo.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                // User already exists - just ensure they have admin role and system user flag
                // DO NOT reset password - use the Admin UI to change passwords
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
