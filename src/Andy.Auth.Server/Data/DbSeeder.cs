using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Seeds the database with initial data (clients, test users, etc.)
/// </summary>
public class DbSeeder
{
    /// <summary>
    /// Deterministic <c>ApplicationUser.Id</c> (and JWT <c>sub</c> claim) for
    /// <c>test@andy.local</c> in non-Production environments. Exposed so
    /// downstream ecosystem services (andy-rbac, consumer integration tests)
    /// can pre-bind roles and permissions to this subject without runtime
    /// coordination. See rivoli-ai/andy-auth#56.
    /// </summary>
    public const string TestUserWellKnownId = "00000000-0000-0000-0000-000000000001";

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
        await SeedFromManifestsAsync();
        await SeedScopesAsync();
        await SeedClientsAsync();
        await SeedTestUserAsync();
    }

    /// <summary>
    /// Manifest-driven scope + OAuth client registration. Reads registration.json
    /// manifests from each Andy service and emits the corresponding OpenIddict
    /// scopes and application descriptors. Idempotent: uses delete-then-create so
    /// re-runs pick up manifest changes. Services whose manifests cover their
    /// registration will be handled here; the legacy hardcoded
    /// SeedScopesAsync / SeedClientsAsync methods below still run afterwards
    /// until every service has a committed manifest.
    /// </summary>
    private async Task SeedFromManifestsAsync()
    {
        var loaderLogger = _serviceProvider.GetRequiredService<ILogger<RegistrationManifestLoader>>();
        var loader = new RegistrationManifestLoader(_configuration, loaderLogger);
        var manifests = loader.LoadAll();

        if (manifests.Count == 0)
        {
            _logger.LogInformation("No registration manifests found; falling back to legacy hardcoded seeding.");
            return;
        }

        var scopeManager = _serviceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var appManager = _serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        foreach (var manifest in manifests)
        {
            if (manifest.Auth is null) continue;

            await CreateOrUpdateScopeAsync(scopeManager, manifest);

            if (manifest.Auth.ApiClient is not null)
            {
                await CreateOrUpdateClientAsync(appManager, manifest, manifest.Auth.ApiClient, isApi: true);
            }
            if (manifest.Auth.WebClient is not null)
            {
                await CreateOrUpdateClientAsync(appManager, manifest, manifest.Auth.WebClient, isApi: false);
            }
            if (manifest.Auth.CliClient is not null)
            {
                await CreateOrUpdateClientAsync(appManager, manifest, manifest.Auth.CliClient, isApi: false);
            }
        }
    }

    private async Task CreateOrUpdateScopeAsync(IOpenIddictScopeManager scopeManager, RegistrationManifest manifest)
    {
        var audience = manifest.Auth!.Audience;
        var existing = await scopeManager.FindByNameAsync(audience);
        if (existing is not null) return;

        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = audience,
            DisplayName = $"{manifest.Service.DisplayName} API",
            Resources = { audience },
        });
        _logger.LogInformation("[manifest] Created API resource scope: {Audience}", audience);
    }

    private async Task CreateOrUpdateClientAsync(
        IOpenIddictApplicationManager appManager,
        RegistrationManifest manifest,
        RegistrationOAuthClient client,
        bool isApi)
    {
        var existing = await appManager.FindByClientIdAsync(client.ClientId);
        if (existing is not null)
        {
            await appManager.DeleteAsync(existing);
            _logger.LogInformation("[manifest] Deleted existing OAuth client: {ClientId}", client.ClientId);
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = client.ClientId,
            DisplayName = client.DisplayName,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
        };

        var isConfidential = string.Equals(client.ClientType, "confidential", StringComparison.OrdinalIgnoreCase)
                              || (client.ClientType is null && isApi);
        if (isConfidential)
        {
            descriptor.ClientSecret = ResolveClientSecret(client);
        }
        else
        {
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Public;
        }

        var grantTypes = client.GrantTypes ?? Array.Empty<string>();
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        if (grantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }
        if (grantTypes.Contains("refresh_token", StringComparer.OrdinalIgnoreCase))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        }
        if (grantTypes.Contains("client_credentials", StringComparer.OrdinalIgnoreCase))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        }
        if (grantTypes.Contains("device_code", StringComparer.OrdinalIgnoreCase))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.DeviceCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization);
        }
        if (isConfidential)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
        }

        foreach (var scope in client.Scopes ?? Array.Empty<string>())
        {
            descriptor.Permissions.Add(scope);
        }

        var redirectUris = CollectRedirectUris(manifest, client, postLogout: false);
        foreach (var uri in redirectUris)
        {
            if (Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            {
                descriptor.RedirectUris.Add(parsed);
            }
        }
        var postLogoutUris = CollectRedirectUris(manifest, client, postLogout: true);
        foreach (var uri in postLogoutUris)
        {
            if (Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            {
                descriptor.PostLogoutRedirectUris.Add(parsed);
            }
        }

        await appManager.CreateAsync(descriptor);
        _logger.LogInformation("[manifest] Created OAuth client: {ClientId} ({Type})",
            client.ClientId, isConfidential ? "confidential" : "public");
    }

    private static IEnumerable<string> CollectRedirectUris(
        RegistrationManifest manifest,
        RegistrationOAuthClient client,
        bool postLogout)
    {
        var clientUris = postLogout ? client.PostLogoutRedirectUris : client.RedirectUris;
        if (clientUris is not null)
        {
            foreach (var u in clientUris) yield return u;
        }
        var prod = manifest.Auth?.ProductionUris;
        var prodUris = postLogout ? prod?.PostLogoutRedirectUris : prod?.RedirectUris;
        if (prodUris is not null)
        {
            foreach (var u in prodUris) yield return u;
        }
    }

    private string ResolveClientSecret(RegistrationOAuthClient client)
    {
        if (!string.IsNullOrWhiteSpace(client.ClientSecretEnvVar))
        {
            var value = Environment.GetEnvironmentVariable(client.ClientSecretEnvVar!);
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        // Dev fallback matches the legacy hardcoded pattern.
        return $"{client.ClientId}-secret-change-in-production";
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

    /// <summary>
    /// Legacy hardcoded scope registration, kept for services that do not yet
    /// ship a <c>config/registration.json</c> manifest. Scope declarations for
    /// the in-scope Andy services (andy-auth, andy-rbac, andy-docs, andy-code-index,
    /// andy-containers, andy-issues, andy-agents, andy-tasks, andy-policies,
    /// andy-models) moved to <see cref="SeedFromManifestsAsync"/>.
    ///
    /// Only two service scopes remain hardcoded here:
    /// - <c>urn:andy-narration-api</c> and <c>urn:andy-subscription-api</c>
    ///   (services not in the Conductor-embedded scope).
    /// - <c>andy-rbac</c> (bare) — legacy audience. The canonical form is
    ///   <c>urn:andy-rbac-api</c>, created from the andy-rbac manifest. The
    ///   bare form is preserved until rivoli-ai/andy-rbac#42 completes the
    ///   rename across every consumer.
    /// </summary>
    private async Task SeedScopesAsync()
    {
        var manager = _serviceProvider.GetRequiredService<IOpenIddictScopeManager>();

        if (await manager.FindByNameAsync("urn:andy-narration-api") == null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "urn:andy-narration-api",
                DisplayName = "Andy Narration API",
                Resources = { "urn:andy-narration-api" }
            });
            _logger.LogInformation("Created API resource scope: urn:andy-narration-api");
        }

        if (await manager.FindByNameAsync("urn:andy-subscription-api") == null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "urn:andy-subscription-api",
                DisplayName = "Andy Subscription API",
                Resources = { "urn:andy-subscription-api" }
            });
            _logger.LogInformation("Created API resource scope: urn:andy-subscription-api");
        }

        // urn:andy-rbac-api comes from the andy-rbac manifest. The legacy
        // bare "andy-rbac" scope was removed as part of rivoli-ai/andy-rbac#42.
    }

    private async Task SeedClientsAsync()
    {
        var manager = _serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // andy-docs-api: now manifest-driven via andy-docs/config/registration.json.

        // Also clean up legacy lexipro-api client if it exists.
        var legacyClient = await manager.FindByClientIdAsync("lexipro-api");
        if (legacyClient != null)
        {
            await manager.DeleteAsync(legacyClient);
            _logger.LogInformation("Deleted legacy OAuth client: lexipro-api");
        }

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
                "scp:urn:andy-code-index-api",  // Permission to request andy-code-index-api resource

                OpenIddictConstants.Permissions.ResponseTypes.Code
                // MCP resource permissions appended below from the
                // config-driven `OpenIddict:Resources` list so seeded
                // clients stay in lock-step with Program.cs /
                // DynamicClientRegistrationController. One list, one
                // source of truth, per deployment mode.
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

        AppendConfiguredMcpResources(claudeDescriptor);
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
                "scp:urn:andy-code-index-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code
                // MCP resource permissions appended below from config.
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

        AppendConfiguredMcpResources(chatGptDescriptor);
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
                "scp:urn:andy-code-index-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                // Andy Code Index MCP resources
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5101/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5100/mcp",
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
                "scp:urn:andy-code-index-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                // Andy Code Index MCP resources
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5101/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5100/mcp",
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
                "scp:urn:andy-code-index-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                // Andy Code Index MCP resources
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5101/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5100/mcp",
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
                "scp:urn:andy-code-index-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Allow requesting resource servers (for MCP)
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-uat.up.railway.app/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://andy-docs-api.rivoli.ai/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:7001/mcp",
                // Andy Code Index MCP resources
                OpenIddictConstants.Permissions.Prefixes.Resource + "https://localhost:5101/mcp",
                OpenIddictConstants.Permissions.Prefixes.Resource + "http://localhost:5100/mcp",
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

        // Andy Agentic Web Client (SPA)
        var agenticWebClient = await manager.FindByClientIdAsync("andy-agentic-web");
        if (agenticWebClient != null)
        {
            await manager.DeleteAsync(agenticWebClient);
            _logger.LogInformation("Deleted existing OAuth client: andy-agentic-web");
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "andy-agentic-web",
            DisplayName = "Andy Agentic Web",
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
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris =
            {
                new Uri("http://localhost:4200"),
                new Uri("http://localhost:4200/callback"),
                new Uri("https://localhost:4200"),
                new Uri("https://localhost:4200/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("http://localhost:4200"),
                new Uri("https://localhost:4200")
            }
        });

        _logger.LogInformation("Created OAuth client: andy-agentic-web");

        // andy-code-index-web, andy-containers-web, andy-containers-cli:
        // manifest-driven via each service's config/registration.json.

        // andy-rbac-web: manifest-driven via andy-rbac/config/registration.json.

        // Conductor macOS Client (native desktop app)
        var conductorMacClient = await manager.FindByClientIdAsync("conductor-mac");
        if (conductorMacClient != null)
        {
            await manager.DeleteAsync(conductorMacClient);
            _logger.LogInformation("Deleted existing OAuth client: conductor-mac");
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "conductor-mac",
            DisplayName = "Conductor macOS",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.Endpoints.Revocation,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",
                "scp:urn:andy-code-index-api",
                // conductor-mac talks to andy-issues (backlog import,
                // repo registry, etc.); without this permission the
                // JWT emitted for Conductor has aud=[docs, code-index]
                // only, and andy-issues' JwtBearer middleware rejects
                // every request with IDX10214 audience mismatch. See
                // rivoli-ai/conductor#545 for the broader sweep.
                "scp:urn:andy-issues-api",
                // Conductor also talks directly to andy-containers
                // (sandbox provisioning, template catalog) and andy-rbac
                // (org membership checks). Without these, the same
                // IDX10214 audience mismatch hits those services and
                // their ClaimsPrincipal stays anonymous. Part of the
                // conductor#545 sweep.
                "scp:urn:andy-containers-api",
                "scp:urn:andy-rbac-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris =
            {
                new Uri("http://127.0.0.1/conductor/callback"),
                new Uri("http://localhost/conductor/callback"),
                new Uri("conductor://callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("http://127.0.0.1/conductor/logout"),
                new Uri("http://localhost/conductor/logout")
            }
        });

        _logger.LogInformation("Created OAuth client: conductor-mac");

        // Andy Subscription Web Client (SPA)
        var subscriptionWebClient = await manager.FindByClientIdAsync("andy-subscription-web");
        if (subscriptionWebClient != null)
        {
            await manager.DeleteAsync(subscriptionWebClient);
            _logger.LogInformation("Deleted existing OAuth client: andy-subscription-web");
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "andy-subscription-web",
            DisplayName = "Andy Subscription Web",
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
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-subscription-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris =
            {
                new Uri("https://localhost:4202/callback"),
                new Uri("http://localhost:4202/callback"),
                new Uri("https://localhost:5320/callback"),
                new Uri("http://localhost:5320/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:4202/"),
                new Uri("https://localhost:4202/login"),
                new Uri("http://localhost:4202/"),
                new Uri("http://localhost:4202/login"),
                new Uri("https://localhost:5320/"),
                new Uri("https://localhost:5320/login"),
                new Uri("http://localhost:5320/"),
                new Uri("http://localhost:5320/login")
            }
        });

        _logger.LogInformation("Created OAuth client: andy-subscription-web");

        // Andy Subscription CLI Client
        var subscriptionCliClient = await manager.FindByClientIdAsync("andy-subscription-cli");
        if (subscriptionCliClient != null)
        {
            await manager.DeleteAsync(subscriptionCliClient);
            _logger.LogInformation("Deleted existing OAuth client: andy-subscription-cli");
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "andy-subscription-cli",
            DisplayName = "Andy Subscription CLI",
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
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-subscription-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris =
            {
                new Uri("http://127.0.0.1/callback"),
                new Uri("http://localhost/callback")
            }
        });

        _logger.LogInformation("Created OAuth client: andy-subscription-cli");

        // Andy Narration Web Client
        var andyNarrationWebClient = await manager.FindByClientIdAsync("andy-narration-web");
        if (andyNarrationWebClient != null)
        {
            await manager.DeleteAsync(andyNarrationWebClient);
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "andy-narration-web",
            DisplayName = "Andy Narration Web",
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
                OpenIddictConstants.Permissions.Scopes.Roles,
                "scp:urn:andy-narration-api",

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris =
            {
                new Uri("https://localhost:5310/callback"),
                new Uri("https://localhost:4200/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:5310/"),
                new Uri("https://localhost:4200/")
            }
        });

        _logger.LogInformation("Created OAuth client: andy-narration-web");

        // andy-issues-api, andy-issues-web, andy-agents-api, andy-agents-web,
        // andy-tasks-api, andy-tasks-web: manifest-driven via each service's
        // config/registration.json.
    }

    /// <summary>
    /// Generates a random password that meets ASP.NET Identity requirements
    /// </summary>
    /// <summary>
    /// Appends `rst:<resource>` permissions to the descriptor for every
    /// entry in <c>OpenIddict:Resources</c> config. Called from the
    /// claude-desktop and chatgpt seeders so their allowed MCP resource
    /// list stays in lock-step with the central config list — the same
    /// list <c>Program.cs</c> registers at startup and
    /// <c>DynamicClientRegistrationController</c> grants to DCR clients.
    ///
    /// Without this, hardcoded MCP URLs in the seeder would diverge from
    /// runtime config per deployment mode (Development/Docker/Embedded/
    /// Production).
    /// </summary>
    internal void AppendConfiguredMcpResources(OpenIddictApplicationDescriptor descriptor)
    {
        var resources = _configuration
            .GetSection("OpenIddict:Resources")
            .Get<string[]>() ?? Array.Empty<string>();
        foreach (var resource in resources)
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Prefixes.Resource + resource);
        }
    }

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
                    Id = TestUserWellKnownId,
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
                    _logger.LogInformation("Created test user: {Email} with deterministic Id {UserId} in {Environment} environment", testEmail, testUser.Id, environment);
                }
                else
                {
                    _logger.LogWarning("Failed to create test user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                // Id is the primary key + FK anchor for Identity-related rows; mutating
                // it in place would orphan history. If an older non-deterministic Id
                // exists from a pre-#56 upgrade, log and leave alone — operators can
                // delete + recreate manually if they need the deterministic Id.
                if (existingTestUser.Id != TestUserWellKnownId)
                {
                    _logger.LogWarning(
                        "Test user {Email} exists with Id {ActualId} rather than the well-known {ExpectedId}. " +
                        "Downstream services that pre-bind roles by Id (andy-rbac et al) will not match this user. " +
                        "To reset: delete the user via the admin UI and restart andy-auth.",
                        testEmail, existingTestUser.Id, TestUserWellKnownId);
                }

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
