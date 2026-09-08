using Andy.Auth.Server.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
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

    /// <summary>
    /// Deterministic <c>ApplicationUser.Id</c> for <c>viewer@andy.local</c>, the
    /// no-special-permissions counterpart to <see cref="TestUserWellKnownId"/>.
    /// Downstream services that pre-bind roles via manifest <c>testUserRole</c>
    /// only target <see cref="TestUserWellKnownId"/>; this viewer subject is
    /// deliberately left unbound so consumer E2E tests have an authenticated-
    /// but-unauthorized identity for 403 assertions. See
    /// rivoli-ai/andy-policies#109.
    /// </summary>
    public const string ViewerUserWellKnownId = "00000000-0000-0000-0000-000000000002";

    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DbSeeder> _logger;
    private readonly IHostEnvironment _environment;

    public DbSeeder(
        IServiceProvider serviceProvider,
        IConfiguration configuration,
        ILogger<DbSeeder> logger,
        IHostEnvironment environment)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _logger = logger;
        _environment = environment;
    }

    public async Task SeedAsync()
    {
        await SeedRolesAsync();
        await SeedFromManifestsAsync();
        await RemoveLegacyClientsAsync();
        await SeedTestUserAsync();
    }

    /// <summary>
    /// Manifest-driven scope + OAuth client registration. Reads registration.json
    /// manifests from each Andy service and emits the corresponding OpenIddict
    /// scopes and application descriptors. Updates preserve application identity
    /// and grants; configured registrations precede bundled external defaults.
    /// </summary>
    public async Task SeedFromManifestsAsync()
    {
        var loaderLogger = _serviceProvider.GetRequiredService<ILogger<RegistrationManifestLoader>>();
        var loader = new RegistrationManifestLoader(_configuration, loaderLogger);
        var manifests = loader.LoadAll();

        if (manifests.Count == 0)
        {
            _logger.LogInformation("No registration manifests found.");
            return;
        }

        var scopeManager = _serviceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var appManager = _serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var seededClients = new HashSet<string>(StringComparer.Ordinal);
        foreach (var manifest in manifests)
        {
            if (manifest.Auth is null) continue;

            if (manifest.Auth.RegisterAudience) await CreateOrUpdateScopeAsync(scopeManager, manifest);

            if (manifest.Auth.ApiClient is not null && seededClients.Add(manifest.Auth.ApiClient.ClientId))
            {
                await CreateOrUpdateClientAsync(appManager, manifest, manifest.Auth.ApiClient, isApi: true);
            }
            if (manifest.Auth.WebClient is not null && seededClients.Add(manifest.Auth.WebClient.ClientId))
            {
                await CreateOrUpdateClientAsync(appManager, manifest, manifest.Auth.WebClient, isApi: false);
            }
            if (manifest.Auth.CliClient is not null && seededClients.Add(manifest.Auth.CliClient.ClientId))
            {
                await CreateOrUpdateClientAsync(appManager, manifest, manifest.Auth.CliClient, isApi: false);
            }
        }
    }

    private async Task CreateOrUpdateScopeAsync(IOpenIddictScopeManager scopeManager, RegistrationManifest manifest)
    {
        var audience = manifest.Auth!.Audience;

        // Tokens carrying this scope get every entry below as an `aud` claim.
        // Besides the audience URN itself, include the service's API client id:
        // RFC 8693 token exchange (OBO) requires the subject token to name the
        // exchanging CLIENT among its audiences or presenters — OpenIddict
        // rejects the exchange with ID2187 otherwise. The URN alone never
        // matches the client id, which silently broke every service-initiated
        // OBO exchange (andy-containers → andy-models) and forced the M2M
        // fallback that mislabels the acting user.
        var resources = new List<string> { audience };
        var apiClientId = manifest.Auth.ApiClient?.ClientId;
        if (!string.IsNullOrWhiteSpace(apiClientId) && !resources.Contains(apiClientId))
        {
            resources.Add(apiClientId);
        }

        var existing = await scopeManager.FindByNameAsync(audience);
        if (existing is null)
        {
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = audience,
                DisplayName = $"{manifest.Service.DisplayName} API",
            };
            foreach (var resource in resources)
            {
                descriptor.Resources.Add(resource);
            }
            await scopeManager.CreateAsync(descriptor);
            _logger.LogInformation("[manifest] Created API resource scope: {Audience}", audience);
            return;
        }

        // Reconcile an existing scope's resources so already-seeded databases
        // pick up manifest changes (the previous early-return meant they never
        // did — deployed environments were stuck with creation-time resources).
        var currentResources = await scopeManager.GetResourcesAsync(existing);
        var missing = resources.Where(r => !currentResources.Contains(r, StringComparer.Ordinal)).ToList();
        if (missing.Count == 0) return;

        var updateDescriptor = new OpenIddictScopeDescriptor();
        await scopeManager.PopulateAsync(updateDescriptor, existing);
        foreach (var resource in missing)
        {
            updateDescriptor.Resources.Add(resource);
        }
        await scopeManager.UpdateAsync(existing, updateDescriptor);
        _logger.LogInformation(
            "[manifest] Updated API resource scope {Audience}: added resources {Resources}",
            audience, string.Join(", ", missing));
    }

    private async Task CreateOrUpdateClientAsync(
        IOpenIddictApplicationManager appManager,
        RegistrationManifest manifest,
        RegistrationOAuthClient client,
        bool isApi)
    {
        var existing = await appManager.FindByClientIdAsync(client.ClientId);
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
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
            descriptor.ClientSecret = ResolveClientSecret(client);
        }
        else
        {
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Public;
        }

        if (client.RequireDpop)
            descriptor.Requirements.Add(Andy.Auth.Server.Services.Dpop.DpopBinding.Requirement);

        if (client.RequirePar)
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);

        var grantTypes = client.GrantTypes ?? Array.Empty<string>();
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        if (grantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
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
        if (grantTypes.Contains(Services.Ciba.CibaOptions.GrantType, StringComparer.Ordinal))
        {
            if (!isConfidential || client.BackchannelTokenDeliveryMode != "poll")
                throw new InvalidOperationException("CIBA registration requires a confidential client and poll delivery mode.");
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.GrantType + Services.Ciba.CibaOptions.GrantType);
            descriptor.Properties[Services.Ciba.CibaOptions.DeliveryModeProperty] = System.Text.Json.JsonSerializer.SerializeToElement("poll");
        }
        // RFC 8693 token exchange. Manifests opt in via either the short
        // alias "token_exchange" or the canonical URN. The (actor,
        // audience) allow-list in TokenExchange:Policies is the real
        // gate at request time; this permission just lets the client
        // reach the handler. Drives Epic IDP (rivoli-ai/conductor#1246).
        if (grantTypes.Contains("token_exchange", StringComparer.OrdinalIgnoreCase)
            || grantTypes.Contains(Services.TokenExchangeConstants.GrantType, StringComparer.OrdinalIgnoreCase))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Prefixes.GrantType + Services.TokenExchangeConstants.GrantType);

            // OpenIddict additionally enforces a per-client `rsr:<audience>`
            // permission when the request carries a `resource` parameter
            // (ID2192: "This client application is not allowed to use the
            // specified resource(s)"). For token-exchange actors the set of
            // downstream audiences they may target is already declared in
            // TokenExchange:Policies, so derive the resource permissions
            // from that single source of truth rather than introducing a
            // parallel manifest field. See rivoli-ai/conductor#943.
            foreach (var audience in GetTokenExchangeAudiencesFor(client.ClientId))
            {
                descriptor.Permissions.Add(
                    OpenIddictConstants.Permissions.Prefixes.Resource + audience);
            }
        }
        if (isConfidential)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
        }

        foreach (var scope in client.Scopes ?? Array.Empty<string>())
        {
            descriptor.Permissions.Add(scope.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.Ordinal)
                ? scope : OpenIddictConstants.Permissions.Prefixes.Scope + scope);
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

        // OpenIddict enforces a per-client endpoint permission for RP-initiated
        // logout, so a client with registered post-logout URIs also needs
        // `ept:end_session` or its logout request is rejected. The endpoint
        // itself only became reachable in andy-auth#151 — before that, these
        // URIs were dead config.
        if (descriptor.PostLogoutRedirectUris.Count > 0)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
        }

        if (client.RequirePkce)
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        if (client.UseConfiguredMcpResources) AppendConfiguredMcpResources(descriptor);
        if (existing is null) await appManager.CreateAsync(descriptor);
        else await appManager.UpdateAsync(existing, descriptor);
        _logger.LogInformation("[manifest] Reconciled OAuth client: {ClientId} ({Type})",
            client.ClientId, isConfidential ? "confidential" : "public");
    }

    private List<TokenExchangePolicyEntry>? _tokenExchangePoliciesCache;

    /// <summary>
    /// Returns the downstream audiences this client is permitted to target
    /// via RFC 8693 token exchange, as declared in
    /// <c>TokenExchange:Policies</c>. The list is loaded from
    /// <see cref="IConfiguration"/> once per seeder instance and cached.
    /// Matching is case-insensitive on the actor client id.
    /// </summary>
    private IEnumerable<string> GetTokenExchangeAudiencesFor(string clientId)
    {
        if (_tokenExchangePoliciesCache is null)
        {
            var settings = _configuration
                .GetSection(TokenExchangeSettings.SectionName)
                .Get<TokenExchangeSettings>();
            _tokenExchangePoliciesCache = settings?.Policies ?? new List<TokenExchangePolicyEntry>();
        }

        foreach (var entry in _tokenExchangePoliciesCache)
        {
            if (string.Equals(entry.ActorClientId, clientId, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(entry.Audience))
            {
                yield return entry.Audience;
            }
        }
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

        // Outside Development we refuse to fall back to a deterministic
        // "<clientId>-secret-change-in-production" string — that would ship a
        // well-known credential to UAT/Staging/Production. See andy-auth#47.
        //
        // PV epic follow-up (2026-05-14): `Embedded` is the environment
        // Conductor runs andy-auth in when bundled inside the macOS app.
        // That is by definition a developer's local machine — the same
        // policy as `Development` applies. Without this branch, the
        // entire seeder crashes on the FIRST confidential-client
        // manifest (andy-containers-api) and downstream client edits
        // (conductor-mac scope grants, etc.) never run; the symptom is
        // a stale conductor-mac record in the DB and 401 errors on
        // every newer service Conductor calls.
        var isEmbedded = string.Equals(_environment.EnvironmentName, "Embedded", StringComparison.OrdinalIgnoreCase);
        if (!_environment.IsDevelopment() && !isEmbedded)
        {
            throw new InvalidOperationException(
                $"Confidential OAuth client '{client.ClientId}' has no secret configured: " +
                $"set the '{client.ClientSecretEnvVar ?? "<ClientSecretEnvVar>"}' " +
                $"environment variable in {_environment.EnvironmentName}. " +
                "The dev-only fallback is disabled outside the Development environment.");
        }

        // Dev / Embedded fallback matches the legacy hardcoded pattern.
        // Local-dev environments only — UAT/Staging/Production fail fast above.
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

    private async Task RemoveLegacyClientsAsync()
    {
        var manager = _serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        foreach (var id in new[] { "lexipro-api", "wagram-web" })
        {
            var legacy = await manager.FindByClientIdAsync(id);
            if (legacy is not null) await manager.DeleteAsync(legacy);
        }
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

    /// <summary>
    /// Generates a 16-character password meeting Identity's default complexity
    /// rules (≥1 upper, lower, digit, special) using a cryptographically
    /// secure RNG. Replaces the prior <see cref="System.Random"/>
    /// implementation which produced predictable output across processes
    /// started in the same tick. See andy-auth#48.
    /// </summary>
    internal static string GenerateRandomPassword()
    {
        const string upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowerCase = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string special = "!@#$%^&*";

        var password = new char[16];

        // Ensure at least one of each required character type. Each call to
        // RandomNumberGenerator.GetInt32 reads fresh entropy from the OS CSPRNG.
        password[0] = upperCase[System.Security.Cryptography.RandomNumberGenerator.GetInt32(upperCase.Length)];
        password[1] = lowerCase[System.Security.Cryptography.RandomNumberGenerator.GetInt32(lowerCase.Length)];
        password[2] = digits[System.Security.Cryptography.RandomNumberGenerator.GetInt32(digits.Length)];
        password[3] = special[System.Security.Cryptography.RandomNumberGenerator.GetInt32(special.Length)];

        // Fill the rest with random characters from all types
        var allChars = upperCase + lowerCase + digits + special;
        for (int i = 4; i < password.Length; i++)
        {
            password[i] = allChars[System.Security.Cryptography.RandomNumberGenerator.GetInt32(allChars.Length)];
        }

        // Fisher-Yates shuffle so the four guaranteed character classes don't
        // always appear at indexes 0-3.
        for (int i = password.Length - 1; i > 0; i--)
        {
            int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
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
                    // Outside Development the seeder must not invent admin
                    // credentials — historically the generated password was
                    // logged at WARN level (andy-auth#48), which leaked
                    // permanent admin access into log aggregators. Fail fast
                    // so operators set the env var explicitly.
                    //
                    // `Embedded` (the environment Conductor uses when bundling
                    // andy-auth inside the macOS app) is treated the same as
                    // Development for this carveout — same policy as the OAuth
                    // client secret seeding at line 243. Without this, the
                    // entire seeder throws on the first admin user and
                    // SeedTestUserAsync never reaches the test@andy.local /
                    // viewer@andy.local creation block below, leaving the
                    // embedded auth DB with roles + OIDC clients but zero
                    // users. See rivoli-ai/andy-auth#100.
                    var isEmbedded = string.Equals(_environment.EnvironmentName, "Embedded", StringComparison.OrdinalIgnoreCase);
                    if (!_environment.IsDevelopment() && !isEmbedded)
                    {
                        throw new InvalidOperationException(
                            $"Admin user '{userInfo.Email}' has no password configured: " +
                            $"set the '{userInfo.PasswordEnvVar}' environment variable in " +
                            $"{_environment.EnvironmentName}. The dev-only generated-password " +
                            "fallback is disabled outside the Development/Embedded environments " +
                            "to avoid leaking credentials into logs.");
                    }

                    password = userInfo.DefaultPassword;
                    // NEVER log the password value, even in Development. Tell
                    // the operator how to override; the password itself only
                    // exists in process memory until CreateAsync hashes it.
                    _logger.LogWarning(
                        "No password set for {Email} via {EnvVar}; using a generated password " +
                        "for this {Environment} run. Set {EnvVar} to choose a stable password.",
                        userInfo.Email, userInfo.PasswordEnvVar, _environment.EnvironmentName, userInfo.PasswordEnvVar);
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
                    // Admin users are required seed data. A failed CreateAsync (e.g. a
                    // malformed/rejected ADMIN_PASSWORD_* that violates the Identity
                    // password policy) previously only logged a warning, leaving the DB
                    // with no admin user while startup still reported ready. Throw so the
                    // startup catch marks readiness failed and /ready stays 503 (#130).
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to create required admin user {Email}: {Errors}",
                        userInfo.Email, errors);
                    throw new InvalidOperationException(
                        $"Required admin user '{userInfo.Email}' could not be seeded: {errors}. " +
                        $"Check the configured password (e.g. {userInfo.PasswordEnvVar}) against the " +
                        "Identity password policy.");
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

        // Seed the well-known test users in LOCAL environments only —
        // Development, Docker, Embedded (andy-auth#54).
        //
        // This used to run in every non-Production environment, which included
        // UAT and Staging. UAT is internet-facing, so every boot re-created
        // `test@andy.local` with the published password `Test123!` and cleared
        // its lockout: a permanent, pre-authenticated foothold that no amount of
        // password policy could close, because the seeder put it back.
        //
        // Two further changes here. The gate reads IHostEnvironment rather than
        // comparing a raw ASPNETCORE_ENVIRONMENT string — the old ordinal
        // compare against "Production" let a lowercase "production", or an
        // environment set through DOTNET_ENVIRONMENT instead, fall through to
        // the seeding branch. And SEED_TEST_USERS provides a deliberate opt-in
        // for anyone who genuinely needs them elsewhere (an ephemeral CI stack),
        // so the decision is explicit rather than a side effect of the
        // environment name.
        var seedTestUsersOptIn = _configuration.GetValue("SEED_TEST_USERS", false);
        var seedTestUsers = _environment.IsLocalOrEmbedded() || seedTestUsersOptIn;

        if (!seedTestUsers)
        {
            _logger.LogInformation(
                "Skipping well-known test users in {Environment}. Set SEED_TEST_USERS=true to override.",
                _environment.EnvironmentName);
        }

        if (seedTestUsers)
        {
            if (seedTestUsersOptIn && !_environment.IsLocalOrEmbedded())
            {
                _logger.LogWarning(
                    "SEED_TEST_USERS is enabled in {Environment}. test@andy.local and viewer@andy.local " +
                    "will be created with a published password. Never set this on an internet-facing " +
                    "deployment (andy-auth#54).",
                    _environment.EnvironmentName);
            }

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
                    _logger.LogInformation("Created test user: {Email} with deterministic Id {UserId} in {Environment} environment", testEmail, testUser.Id, _environment.EnvironmentName);
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

            // Companion viewer user — same password as test@andy.local, deterministic Id
            // ...000000000002, no role bindings from downstream-service manifests. Lets
            // consumer E2E suites (e.g. rivoli-ai/andy-policies#109) drive the authenticated-
            // but-unauthorized path without bootstrapping a user dynamically.
            const string viewerEmail = "viewer@andy.local";
            var existingViewer = await userManager.FindByEmailAsync(viewerEmail);

            if (existingViewer == null)
            {
                var viewerUser = new ApplicationUser
                {
                    Id = ViewerUserWellKnownId,
                    UserName = viewerEmail,
                    Email = viewerEmail,
                    EmailConfirmed = true,
                    FullName = "Viewer User",
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                };

                var result = await userManager.CreateAsync(viewerUser, "Test123!");
                if (result.Succeeded)
                {
                    // Same Identity "User" role as test@andy.local. The distinction
                    // (admin on andy-policies vs not) lives in andy-rbac, not in
                    // andy-auth's Identity roles.
                    await userManager.AddToRoleAsync(viewerUser, "User");
                    _logger.LogInformation(
                        "Created viewer test user: {Email} with deterministic Id {UserId} in {Environment} environment",
                        viewerEmail, viewerUser.Id, _environment.EnvironmentName);
                }
                else
                {
                    _logger.LogWarning(
                        "Failed to create viewer test user: {Errors}",
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                if (existingViewer.Id != ViewerUserWellKnownId)
                {
                    _logger.LogWarning(
                        "Viewer test user {Email} exists with Id {ActualId} rather than the well-known {ExpectedId}. " +
                        "Downstream services that pre-bind roles by Id (andy-rbac et al) will not match this user. " +
                        "To reset: delete the user via the admin UI and restart andy-auth.",
                        viewerEmail, existingViewer.Id, ViewerUserWellKnownId);
                }

                var viewerToken = await userManager.GeneratePasswordResetTokenAsync(existingViewer);
                var viewerResetResult = await userManager.ResetPasswordAsync(existingViewer, viewerToken, "Test123!");
                if (viewerResetResult.Succeeded)
                {
                    _logger.LogInformation("Reset password for viewer test user: {Email}", viewerEmail);
                }

                if (existingViewer.AccessFailedCount > 0 || existingViewer.LockoutEnd != null)
                {
                    existingViewer.AccessFailedCount = 0;
                    existingViewer.LockoutEnd = null;
                    await userManager.UpdateAsync(existingViewer);
                    _logger.LogInformation("Cleared lockout for viewer test user: {Email}", viewerEmail);
                }
            }
        }
    }
}
