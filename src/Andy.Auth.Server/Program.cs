using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Controllers.Api;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Mcp;
using Andy.Auth.Server.Middleware;
using Andy.Auth.Server.Services;
using Andy.Auth.Server.Telemetry;
using Andy.Telemetry;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using OpenTelemetry.Trace;

// Authorization policy gating the MCP tool endpoint. Declared here so the
// registration site (AddAuthorization) and the mapping site (MapMcp) can't
// drift apart.
const string McpAdminPolicy = "McpAdmin";

var builder = WebApplication.CreateBuilder(args);

// Configure Railway PORT environment variable
// In Development, use HTTPS on port 5001. In production (Railway), use HTTP with the PORT env variable.
if (builder.Environment.IsDevelopment())
{
    var urls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
    builder.WebHost.UseUrls(urls ?? "https://localhost:5001");
}
else
{
    var port = Environment.GetEnvironmentVariable("PORT") ?? "5000";
    builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
}

// Configure forwarded headers for Railway's HTTPS proxy
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
                               Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Add services to the container
builder.Services.AddControllersWithViews();

// Configure rate limiting
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.Configure<IpRateLimitPolicies>(builder.Configuration.GetSection("IpRateLimitPolicies"));
builder.Services.AddInMemoryRateLimiting();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

// Configure database provider (SQLite by default for embedded mode,
// PostgreSQL for hosted production deployments). Selectable via
// `Database__Provider=Sqlite|PostgreSql` env var. See
// `Data/DatabaseProviderExtensions.cs` for details.
var dbProvider = DatabaseProviderExtensions.GetDatabaseProvider(builder.Configuration);
var connectionString = DatabaseProviderExtensions.ResolveConnectionString(builder.Configuration, dbProvider);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    DatabaseProviderExtensions.ConfigureDbContext(options, dbProvider, connectionString);
    options.UseOpenIddict();
});

// Configure ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false; // Set to true when email is configured
})
.AddEntityFrameworkStores<ApplicationDbContext>()
// Enforces the account lifecycle flags (suspended / expired / soft-deleted)
// that stock CanSignInAsync ignores — see UserLifecycle (andy-auth#146).
.AddSignInManager<AndyAuthSignInManager>()
.AddDefaultTokenProviders();

// Configure cookie authentication paths
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.LogoutPath = "/Account/Logout";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

// Configure external authentication providers (Azure AD / Microsoft Entra ID)
var azureAdClientId = builder.Configuration["AzureAd:ClientId"];
var azureAdClientSecret = builder.Configuration["AzureAd:ClientSecret"];

if (!string.IsNullOrEmpty(azureAdClientId) && !string.IsNullOrEmpty(azureAdClientSecret))
{
    builder.Services.AddAuthentication()
        .AddMicrosoftAccount(options =>
        {
            options.ClientId = azureAdClientId;
            options.ClientSecret = azureAdClientSecret;

            // Configure tenant (common = multi-tenant, or specific tenant ID)
            var tenantId = builder.Configuration["AzureAd:TenantId"] ?? "common";
            options.AuthorizationEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize";
            options.TokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

            // Request additional scopes
            options.Scope.Add("email");
            options.Scope.Add("profile");

            // Save tokens for later use if needed
            options.SaveTokens = true;

            // Map claims from Azure AD
            options.ClaimActions.MapJsonKey("picture", "picture");
        });
}

// Configure OpenIddict
builder.Services.AddOpenIddict()
    // Register the OpenIddict core components
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    // Register the OpenIddict server components
    .AddServer(options =>
    {
        // `OpenIddict:Server:EncryptionKey` / `:SigningKey` shipped in every
        // settings file and were read by nothing — key material has always
        // come from `OpenIddict:SigningKeys:Path` or the ephemeral fallbacks
        // below. An operator following appsettings.Production.json would set
        // those env vars, believe key material was pinned, and get either a
        // startup error or silently-rotating keys (andy-auth#152). They are
        // gone now; refuse to start if something still sets them, so the same
        // false sense of security can't return unnoticed.
        var strayServerKeys = builder.Configuration
            .GetSection("OpenIddict:Server")
            .GetChildren()
            .Select(c => c.Key)
            .ToArray();
        if (strayServerKeys.Length > 0)
        {
            throw new InvalidOperationException(
                $"Unrecognized configuration under `OpenIddict:Server` ({string.Join(", ", strayServerKeys)}). " +
                "These settings are not read by anything. Signing/encryption key material is configured via " +
                "`OpenIddict:SigningKeys:Path` (persisted RSA keypair) or `OpenIddict:UseEphemeralKeys`. " +
                "See docs/DEPLOYMENT.md.");
        }

        // Fix the issuer so it's consistent regardless of how the server is accessed
        // (localhost vs host.docker.internal, or a reverse proxy like Conductor's
        // unified proxy on port 9100). Read from config so each deployment mode
        // (Development/Docker/Embedded) can pin the issuer that matches its own
        // exposure URL. Conductor's embedded mode sets this via the
        // `OpenIddict__Issuer` env var (see Conductor/Core/ServiceHost/Services/
        // AuthServiceConfig.swift); standalone `dotnet run` reads it from
        // appsettings.Development.json.
        var configuredIssuer = builder.Configuration["OpenIddict:Issuer"];
        if (string.IsNullOrWhiteSpace(configuredIssuer))
        {
            throw new InvalidOperationException(
                "OpenIddict:Issuer must be configured. Set it in appsettings.<env>.json " +
                "or via the OpenIddict__Issuer environment variable. See " +
                "andy-service-template/docs/ports.md for mode-specific issuer URLs.");
        }
        options.SetIssuer(new Uri(configuredIssuer));

        // Enable the authorization, token, introspection, and revocation endpoints
        // Note: userinfo and logout are handled by custom controller endpoints
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetRevocationEndpointUris("connect/revoke")
            // RFC 8628 device authorization grant. /connect/device starts
            // the flow (issues device_code/user_code); /connect/verify is
            // the user-facing endpoint where the operator enters the
            // user_code, signs in, and authorizes the request. The CLI
            // polls /connect/token with grant_type=urn:ietf:params:oauth:
            // grant-type:device_code until the user completes verification.
            .SetDeviceAuthorizationEndpointUris("connect/device")
            .SetEndUserVerificationEndpointUris("connect/verify")
            // OIDC RP-Initiated Logout. Registering the endpoint is what makes
            // `GetOpenIddictServerRequest()` return a parsed logout request in
            // AuthorizationController.Logout — without it that call returned
            // null, `post_logout_redirect_uri` was always ignored, every
            // logout landed on "/", and `end_session_endpoint` never appeared
            // in discovery (andy-auth#151). Registration is also what makes
            // OpenIddict validate the supplied post_logout_redirect_uri
            // against the client's registered list, so the redirect below is
            // not an open redirect.
            .SetEndSessionEndpointUris("connect/logout");

        // Add registration_endpoint to discovery document for DCR (RFC 7591)
        // OpenIddict doesn't natively support DCR, so we add it via a custom handler
        options.AddEventHandler<OpenIddict.Server.OpenIddictServerEvents.HandleConfigurationRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                var baseUri = context.BaseUri?.ToString().TrimEnd('/') ?? "";
                context.Metadata["registration_endpoint"] = $"{baseUri}/connect/register";
                return default;
            })
            .SetOrder(OpenIddict.Server.OpenIddictServerHandlers.Discovery.AttachEndpoints.Descriptor.Order + 1));

        // Enable the authorization code flow and refresh token flow.
        // Require PKCE for every auth-code exchange — public clients
        // (claude-desktop, conductor-mac, every web SPA) face on-device
        // code-interception attacks without it, and confidential clients
        // benefit per OAuth 2.1 / RFC 9700. Only S256 is accepted; the
        // existing test fixtures and oauth-python helpers already send
        // it. Closes andy-auth#46.
        options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow()
            // Device flow for headless CLIs (andy-mcp-proxy stdio bridge,
            // future IDE plugins). Per-client opt-in: only clients seeded
            // with the device_code grant can use this flow (see DbSeeder).
            .AllowDeviceAuthorizationFlow()
            // RFC 8693 OAuth 2.0 Token Exchange. The platform's primitive
            // for cross-service identity propagation: when a service
            // receives a user request and calls a downstream service, it
            // exchanges (user JWT + its own M2M credential) for a new
            // token whose `sub` is the user, whose `act` is the calling
            // service, and whose `aud` is the downstream service.
            // Per-client opt-in lives in each consumer's manifest
            // (registration.json); the (actor, audience) allow-list lives
            // in TokenExchange:Policies in config (see TokenExchangeSettings).
            // Drives Epic IDP (rivoli-ai/conductor#1246).
            .AllowCustomFlow(TokenExchangeConstants.GrantType);

        // Register encryption and signing keys
        //
        // Three deployment shapes, three strategies:
        //
        // 1. Embedded (Conductor desktop app) — persisted RSA keys on disk.
        //    Keys live at `OpenIddict:SigningKeys:Path` (Conductor sets this
        //    to `~/.conductor/keys`). The JWKS `kid` must be stable across
        //    process restarts because the desktop app relaunches frequently
        //    and holds long-lived tokens in the Keychain. Ephemeral keys
        //    would invalidate every cached token on every relaunch.
        //
        // 2. Development / Staging / UAT — ephemeral keys are fine:
        //    developers re-auth via browser on reload, CI tests mint fresh
        //    tokens per run, neither cares about cross-restart JWKS.
        //
        // 3. Production — X.509 certificates from key vault; ephemeral keys
        //    can be opted into via `OpenIddict:UseEphemeralKeys` for
        //    Railway/cloud pods where clients always re-auth.
        if (builder.Environment.IsEmbedded())
        {
            var keysPath = builder.Configuration["OpenIddict:SigningKeys:Path"];
            if (string.IsNullOrWhiteSpace(keysPath))
            {
                throw new InvalidOperationException(
                    "Embedded mode requires `OpenIddict:SigningKeys:Path` to point at a " +
                    "writable directory (e.g. `~/.conductor/keys`). Without persisted " +
                    "keys, JWKS rotates on every process start and every cached JWT " +
                    "becomes invalid. See Configuration/PersistedDevelopmentKeys.cs.");
            }

            options.AddPersistedDevelopmentKeys(keysPath)
                   .DisableAccessTokenEncryption();
        }
        else if (builder.Environment.IsDevelopment()
                 || builder.Environment.IsDocker()
                 || builder.Environment.IsEnvironment("Staging")
                 || builder.Environment.IsEnvironment("UAT"))
        {
            // Local-development trust model — devs (or compose-stack
            // consumers) can re-auth on every container respin, so
            // ephemeral keys are fine. Access tokens stay as signed
            // JWT (industry standard); ID tokens remain encrypted.
            options.AddEphemeralEncryptionKey()
                   .AddEphemeralSigningKey()
                   .DisableAccessTokenEncryption();
        }
        else if (builder.Environment.IsProduction())
        {
            // Production prefers persisted RSA keys on a mounted volume
            // (e.g. Railway `/data/keys` per E3-S4) so JWKS `kid` survives
            // redeploys and every previously-issued JWT keeps validating.
            // Falls back to ephemeral keys for stateless cloud pods that
            // explicitly opt in via `OpenIddict:UseEphemeralKeys=true`.
            var keysPath = builder.Configuration["OpenIddict:SigningKeys:Path"];
            var useEphemeralKeys = builder.Configuration.GetValue<bool>("OpenIddict:UseEphemeralKeys", false);

            if (!string.IsNullOrWhiteSpace(keysPath))
            {
                options.AddPersistedDevelopmentKeys(keysPath)
                       .DisableAccessTokenEncryption();
            }
            else if (useEphemeralKeys)
            {
                // Stateless deploy — keys rotate on every restart, every
                // token in flight becomes invalid. Acceptable only when
                // every consumer can re-auth on demand.
                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey()
                       .DisableAccessTokenEncryption();
            }
            else
            {
                throw new InvalidOperationException(
                    "Production requires either `OpenIddict:SigningKeys:Path` (recommended — " +
                    "RSA keypair persisted on a mounted volume so JWKS survives redeploy) " +
                    "or `OpenIddict:UseEphemeralKeys=true` (rotates keys every restart and " +
                    "invalidates every issued token; only safe for stateless pods where " +
                    "every consumer can re-auth on demand).");
            }
        }

        // Register scopes. `andy_auth:oauth_broker` (issue #123) is the dedicated
        // machine broker-service scope that authorizes the OAuth broker callback /
        // exchange-result mutations and status reads without a signed capability.
        // It is granted only to the client-credentials broker client and is
        // distinct from the human `Admin` role, so an admin user cannot forge
        // terminal transitions or read arbitrary authorization status.
        options.RegisterScopes("openid", "profile", "email", "roles", "offline_access",
            "urn:andy-docs-api",
            OAuthAuthorizationsController.BrokerScope);

        // Register MCP resource servers — the audience values that clients
        // can request tokens for via the `resource` parameter. Read from
        // `OpenIddict:Resources` so each deployment mode pins its own set
        // (Mode 1 uses 5xxx ports, Mode 2 uses 7xxx, Conductor Embedded
        // uses http://localhost:9100/<service>/mcp, hosted prod uses the
        // public Railway/rivoli.ai URLs). Config-driven so no mode has to
        // live in the codebase.
        var mcpResources = builder.Configuration
            .GetSection("OpenIddict:Resources")
            .Get<string[]>() ?? Array.Empty<string>();
        if (mcpResources.Length > 0)
        {
            options.RegisterResources(mcpResources);
        }

        // Register API audience resources sourced from the same registration
        // manifests the DbSeeder consumes. OpenIddict's resource validator
        // (event 6273 / OpenIddict-error ID2190) rejects any `resource`
        // parameter not in the static allow-list set here — including the
        // RFC 8693 token-exchange flow where the actor is asking for a
        // downstream service audience like `urn:andy-models-api`. Driving
        // this from the manifests keeps the allow-list aligned with what
        // ships in the bundle without per-environment config drift.
        var manifestLoaderLogger = LoggerFactory.Create(b => b.AddConsole())
            .CreateLogger<RegistrationManifestLoader>();
        var manifestLoader = new RegistrationManifestLoader(
            builder.Configuration, manifestLoaderLogger);
        var manifestAudiences = manifestLoader.LoadAll()
            .Select(m => m.Auth?.Audience)
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (manifestAudiences.Length > 0)
        {
            options.RegisterResources(manifestAudiences);
        }

        // Use reference tokens for refresh tokens only (stored in database, can be revoked)
        // Access tokens are JWTs so they can be validated by external APIs without introspection
        options.UseReferenceRefreshTokens();

        // Register the ASP.NET Core host and configure based on environment
        // Note: userinfo and logout endpoints are custom controllers, not OpenIddict passthrough
        var aspNetCoreBuilder = options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            // /connect/device is handled natively by OpenIddict (it
            // validates client_id + scopes, mints device_code/user_code,
            // returns JSON). Only the user-facing verification UI needs
            // MVC passthrough so we can render the code-entry form and
            // hook into our existing Identity sign-in flow.
            .EnableEndUserVerificationEndpointPassthrough()
            // Logout is rendered/handled by AuthorizationController.Logout.
            .EnableEndSessionEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

        // Allow HTTP for local development, CI, Docker compose stacks, and
        // Conductor's embedded mode (all traffic goes through the unified
        // localhost HTTP proxy on port 9100, so TLS requirement is moot).
        if (builder.Environment.IsLocalOrEmbedded() || builder.Environment.IsEnvironment("Staging") || builder.Environment.IsEnvironment("UAT"))
        {
            aspNetCoreBuilder.DisableTransportSecurityRequirement();
        }
    })
    // Register the OpenIddict validation components
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Configure authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

// Configure authorization
builder.Services.AddAuthorization(options =>
{
    // The MCP tool surface (Mcp/AuthMcpTools.cs) is an admin surface: it can
    // create/delete groups and add or remove any user from any group. Group
    // membership is projected into the `groups` claim at token issuance and
    // downstream services authorize on it, so an unauthenticated-role-checked
    // /mcp let any token holder grant itself any group (andy-auth#145).
    // Mirror the guard the equivalent REST controllers already carry:
    // [Authorize(AuthenticationSchemes = OpenIddict validation, Roles = "Admin")].
    options.AddPolicy(McpAdminPolicy, policy => policy
        .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("Admin"));
});

// Register session management service
builder.Services.AddScoped<SessionService>();

// Tears down tokens/authorizations/sessions when an admin disables an account
// (andy-auth#146) — blocking future sign-ins alone leaves existing refresh
// tokens minting access tokens indefinitely.
builder.Services.AddScoped<IUserAccessRevoker, UserAccessRevoker>();

// Register audit logging service
builder.Services.AddScoped<IAuditService, AuditService>();

// Register Dynamic Client Registration (RFC 7591)
builder.Services.Configure<DcrSettings>(builder.Configuration.GetSection(DcrSettings.SectionName));
builder.Services.AddScoped<DcrService>();
// #120 — startup sweep that removes orphaned DCR applications/tokens left by
// any pre-fix partial registration.
builder.Services.AddScoped<DcrReconciliationService>();

// Register RFC 8693 Token Exchange policy (Epic IDP — rivoli-ai/conductor#1246).
// The TokenExchange:Policies allow-list gates which actor client_ids may
// act on behalf of users for which audiences. See TokenExchangeSettings
// for the full design context.
builder.Services.Configure<TokenExchangeSettings>(
    builder.Configuration.GetSection(TokenExchangeSettings.SectionName));
builder.Services.AddSingleton<ITokenExchangePolicy, TokenExchangePolicy>();
builder.Services.AddSingleton<ISubjectTokenValidator, InProcessSubjectTokenValidator>();

// Role → permission claim projection. Downstream services authorize on a
// flat `permission` claim (e.g. andy-tasks tasks:approvePlan); this maps
// the signed-in user's role bindings onto those strings at token issuance.
builder.Services.Configure<RolePermissionOptions>(
    builder.Configuration.GetSection(RolePermissionOptions.SectionName));
builder.Services.AddScoped<RolePermissionResolver>();

// One claims-principal builder for every user-bearing grant. The auth-code and
// device flows each had their own copy and drifted — device-flow tokens lost
// the `permission` claims entirely (andy-auth#149).
builder.Services.AddScoped<TokenClaimsPrincipalFactory>();

// Shared enabled/approved/secret-expiry gate for dynamically-registered
// clients, used by the authorization, token and device-verify paths
// (andy-auth#153).
builder.Services.AddScoped<DcrClientGate>();

// Register token cleanup background service
builder.Services.AddHostedService<TokenCleanupService>();

// SM.2.2 (rivoli-ai/conductor#2004) — OAuth broker authorization service.
// Owns lifecycle of OAuthAuthorization records: creation, callback classification,
// state transitions, and crash-reconciliation status queries.
builder.Services.AddScoped<OAuthAuthorizationService>();

// Issue #123 — signed one-time capability that authorizes the anonymous OAuth
// broker callback / exchange-result mutations. Minted at /authorize time and
// bound to the authorization id + provider via ASP.NET Data Protection, so
// knowledge of the authorization UUID alone is no longer sufficient authority.
// AddDataProtection is idempotent (Identity already pulls it in) but is declared
// explicitly here to make this endpoint's dependency self-evident.
builder.Services.AddDataProtection();
builder.Services.AddSingleton<OAuthCallbackCapabilityService>();

// Add MCP Server for AI assistant integration with group management
builder.Services
    .AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly();

builder.Services.AddScoped<AuthMcpTools>();

// --- OpenTelemetry (via Andy.Telemetry) ---
// OT4 (rivoli-ai/conductor#1262): andy-auth ships zero OTel DLLs today.
// Wire OTLP export to Conductor's local receiver at :4318. The Conductor
// embedded launcher sets OTEL_EXPORTER_OTLP_ENDPOINT/_PROTOCOL/_SERVICE_NAME
// (see Conductor/Core/ServiceHost/Services/AuthServiceConfig.swift); the
// AndyTelemetry config block under appsettings.Embedded.json is the
// fallback for non-Conductor embedded launches.
//
// Conductor's UnifiedProxy already emits server-side request spans, so
// EnableAspNetCoreInstrumentation stays off here to avoid double-counting.
builder.Services.AddAndyTelemetry(builder.Configuration, o =>
{
    if (string.IsNullOrWhiteSpace(o.ServiceName))
        o.ServiceName = Environment.GetEnvironmentVariable("OTEL_SERVICE_NAME") ?? "andy-auth";
    if (string.IsNullOrWhiteSpace(o.OtlpEndpoint))
        o.OtlpEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
    if (string.IsNullOrWhiteSpace(o.Protocol) || o.Protocol == "grpc")
    {
        var envProtocol = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_PROTOCOL");
        if (!string.IsNullOrWhiteSpace(envProtocol))
            o.Protocol = envProtocol;
    }
    o.ActivitySources.Add(AuthTelemetry.ActivitySourceName);
    o.Meters.Add(AuthTelemetry.MeterName);
    o.EnableAspNetCoreInstrumentation = false;
});
// EF Core tracing is service-specific (not bundled in Andy.Telemetry).
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddEntityFrameworkCoreInstrumentation());

// Configure CORS to allow frontend applications
var allowedOrigins = builder.Configuration.GetSection("CorsOrigins:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowWebClients", policy =>
    {
        if (allowedOrigins.Length > 0)
        {
            policy.WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        }
        else
        {
            // Fallback: Allow localhost for development if no origins configured
            policy.SetIsOriginAllowed(origin => origin.StartsWith("http://localhost:") || origin.StartsWith("https://localhost:"))
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        }
    });

    // Allow MCP clients (Claude Desktop, Cursor, etc.) to access /mcp endpoints
    options.AddPolicy("AllowMcpClients", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// Use forwarded headers - must be first
app.UseForwardedHeaders();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Embedded mode proxies plain HTTP through the Conductor unified
// proxy on port 9100, so HTTPS redirection would trap every request
// in a redirect loop. Skip it in Embedded; keep it everywhere else.
if (!app.Environment.IsEmbedded())
{
    app.UseHttpsRedirection();
}
app.UseDefaultFiles();
app.UseStaticFiles();

// Security headers
// Note: CSP can be toggled via configuration in case of browser-specific issues.
var enableCsp = app.Configuration.GetValue("SecurityHeaders:EnableCsp", false);
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";
    context.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";

    if (enableCsp)
    {
        // Keep this conservative but compatible with inline styles used in Razor views.
        // If you want a strict CSP, move inline styles/scripts to static files and use nonces/hashes.
        context.Response.Headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "base-uri 'self'; " +
            "object-src 'none'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'; " +
            "img-src 'self' data:; " +
            "style-src 'self' 'unsafe-inline'; " +
            "script-src 'self'";
    }

    await next();
});

// RFC 9728 §5.1 — an unauthenticated call to the protected resource must point
// the client at its metadata document, otherwise discovery has no entry point
// and the metadata added above is unreachable in practice (andy-auth#155).
// Sits this high in the pipeline so it observes the final status code after
// authentication/authorization have run.
app.Use(async (context, next) =>
{
    await next();

    if (context.Response.StatusCode == StatusCodes.Status401Unauthorized &&
        context.Request.Path.StartsWithSegments("/mcp") &&
        !context.Response.Headers.ContainsKey("WWW-Authenticate"))
    {
        var metadataUrl =
            $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}" +
            "/.well-known/oauth-protected-resource";

        context.Response.Headers.WWWAuthenticate =
            $"Bearer resource_metadata=\"{metadataUrl}\"";
    }
});

// Add rate limiting
app.UseIpRateLimiting();

app.UseRouting();

app.UseCors("AllowWebClients");

app.UseAuthentication();
app.UseSessionTracking();
app.UseAuthorization();

// --- Health check ---
// Anonymous, dependency-free liveness probe for parity with sibling andy-*
// services (rivoli-ai/andy-auth#116). Conductor's UnifiedProxy probes this via
// 9100/auth/health (the /auth prefix is stripped before it reaches us), so we
// map /health — NOT /auth/health. Must answer without a token and must not
// touch the DB, OpenIddict, or the session store. /health is already in the
// SessionTrackingMiddleware bypass set, so no session cookie is issued.
app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    service = "andy-auth",
    timestamp = DateTime.UtcNow
}))
    .AllowAnonymous()
    .WithName("HealthCheck")
    .ExcludeFromDescription();

// Static test endpoint to debug Safari crash (dev only)
if (app.Environment.IsDevelopment())
{
    app.MapGet("/safari-test", () => Results.Content(
        "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello Safari</h1><p>If you see this, the page works.</p></body></html>",
        "text/html"));
}

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// --- Prometheus metrics scraping (via Andy.Telemetry) ---
// OT4 (rivoli-ai/conductor#1262). Exposes /metrics for the Conductor
// scraper; OTLP push is independent.
app.MapAndyTelemetry();

// --- RFC 9728 Protected Resource Metadata (andy-auth#155) ---
// The MCP authorization spec requires an MCP server acting as a resource
// server to publish this document, and to point at it from the 401 challenge,
// so a client can discover which authorization server guards the resource.
// We shipped neither: `/mcp` returned a bare 401 and a conformant client had
// nowhere to go, despite the README advertising full MCP OAuth 2.1 support.
//
// `resource` is the canonical identifier of this MCP endpoint. It has to match
// what clients send in the RFC 8707 `resource` parameter, which is why it is
// config-driven per deployment mode — Mode 1 uses 5xxx ports, Embedded uses
// the 9100 unified proxy, hosted prod uses the public URL. Falls back to the
// live request origin when unset so local runs work without extra config.
app.MapGet("/.well-known/oauth-protected-resource", (HttpContext context, IConfiguration configuration) =>
{
    var issuer = configuration["OpenIddict:Issuer"]?.TrimEnd('/');

    var resource = configuration["Mcp:ResourceIdentifier"]
        ?? $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/mcp";

    return Results.Ok(new Dictionary<string, object?>
    {
        ["resource"] = resource,
        ["authorization_servers"] = new[] { issuer },
        ["bearer_methods_supported"] = new[] { "header" },
        ["scopes_supported"] = new[] { "openid", "profile", "email", "roles" },
        ["resource_documentation"] = $"{issuer}/docs/",
    });
})
    .AllowAnonymous()
    .WithName("ProtectedResourceMetadata")
    .ExcludeFromDescription();

// Map MCP Server endpoint at /mcp with permissive CORS for MCP clients
// Require authorization so clients (e.g., Claude Desktop) receive an OAuth challenge
app.MapMcp("/mcp")
    .RequireCors("AllowMcpClients")
    .RequireAuthorization(McpAdminPolicy);

// Seed database on startup
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();

        // Schema bootstrap differs by provider:
        //   - PostgreSQL: apply EF migrations (committed under `Migrations/`).
        //   - SQLite: use `EnsureCreated` so a fresh embedded install gets a
        //     schema generated from the current EF model. Migrations for the
        //     SQLite provider are tracked separately under G2.1.
        if (dbProvider == DatabaseProvider.Sqlite)
        {
            await context.Database.EnsureCreatedAsync();

            // EnsureCreated is a no-op on an existing DB, so a schema created
            // by an older binary silently drifts when the model gains a column
            // or table. Heal additive drift in place (missing tables via the
            // model's own generated DDL, missing nullable/defaulted columns
            // via ALTER TABLE ADD COLUMN).
            var healLogger = services
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger(nameof(SqliteSchemaBootstrapper));
            await SqliteSchemaBootstrapper.HealAsync(context, healLogger);
        }
        else
        {
            await context.Database.MigrateAsync();
        }

        // Seed OAuth clients and test data
        var seeder = new DbSeeder(
            services,
            app.Configuration,
            services.GetRequiredService<ILogger<DbSeeder>>(),
            services.GetRequiredService<IHostEnvironment>());
        await seeder.SeedAsync();

        // #120 — reconcile orphaned DCR registrations left by any interrupted
        // registration from before the atomic-registration transaction shipped.
        var reconciler = services.GetRequiredService<DcrReconciliationService>();
        await reconciler.ReconcileAsync();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or seeding the database.");
    }
}

app.Run();

// Make Program class accessible for integration tests
public partial class Program { }
