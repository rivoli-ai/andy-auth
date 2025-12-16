using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Middleware;
using Andy.Auth.Server.Services;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Configure Railway PORT environment variable
// In Development, use HTTPS on port 7088. In production (Railway), use HTTP with the PORT env variable.
if (builder.Environment.IsDevelopment())
{
    builder.WebHost.UseUrls("https://localhost:7088");
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

// Configure PostgreSQL database
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

// Normalize PostgreSQL connection string (convert URI format to key=value format)
if (!string.IsNullOrWhiteSpace(connectionString) &&
    (connectionString.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase) ||
     connectionString.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase)))
{
    connectionString = NormalizePostgresConnectionString(connectionString);
}

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(connectionString);
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
        // Enable the authorization, token, userinfo, logout, introspection, and revocation endpoints
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserinfoEndpointUris("connect/userinfo")
            .SetLogoutEndpointUris("connect/logout")
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetRevocationEndpointUris("connect/revoke");

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

        // Enable the authorization code flow and refresh token flow
        options.AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow();

        // Register encryption and signing keys
        // Use ephemeral keys for development and staging/UAT (avoids certificate management complexity)
        // TODO: For true production, use proper certificates from key vault
        if (builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("Staging") || builder.Environment.IsEnvironment("UAT"))
        {
            options.AddEphemeralEncryptionKey()
                   .AddEphemeralSigningKey()
                   .DisableAccessTokenEncryption();  // Access tokens are signed JWT (industry standard), ID tokens remain encrypted
        }
        else if (builder.Environment.IsProduction())
        {
            // Check if running in Railway/Cloud with ephemeral keys flag
            var useEphemeralKeys = builder.Configuration.GetValue<bool>("OpenIddict:UseEphemeralKeys", false);

            if (useEphemeralKeys)
            {
                // Use ephemeral keys for cloud deployments (Railway, etc.)
                // WARNING: These keys will change on restart, invalidating all tokens
                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey()
                       .DisableAccessTokenEncryption();
            }
            else
            {
                // Production: Load certificates from configuration or key vault
                throw new InvalidOperationException(
                    "Production environment detected. Please configure proper signing and encryption certificates " +
                    "or set OpenIddict:UseEphemeralKeys=true for UAT deployments. " +
                    "See docs/DEPLOYMENT.md for instructions.");
            }
        }

        // Register scopes
        options.RegisterScopes("openid", "profile", "email", "roles", "offline_access");

        // Register MCP resource servers (allows 'resource' parameter in authorization requests)
        // These are the audience values that clients can request tokens for
        options.RegisterResources(
            "https://lexipro-uat.up.railway.app/mcp",
            "https://lexipro-api.rivoli.ai/mcp",
            "https://localhost:7001/mcp",
            "https://localhost:5154/mcp",
            "http://localhost:5154/mcp"
        );

        // Enable reference tokens (opaque tokens stored in database)
        // Reference tokens can be revoked immediately and provide better security audit trails
        // Per-client: Use OpenIddictConstants.Settings.TokenFormat = "Opaque" for reference tokens
        options.UseReferenceAccessTokens()
            .UseReferenceRefreshTokens();

        // Register the ASP.NET Core host and configure based on environment
        var aspNetCoreBuilder = options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

        // Allow HTTP for local development and testing (CI environment)
        if (builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("Staging") || builder.Environment.IsEnvironment("UAT"))
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
builder.Services.AddAuthorization();

// Register session management service
builder.Services.AddScoped<SessionService>();

// Register Dynamic Client Registration (RFC 7591)
builder.Services.Configure<DcrSettings>(builder.Configuration.GetSection(DcrSettings.SectionName));
builder.Services.AddScoped<DcrService>();

// Register token cleanup background service
builder.Services.AddHostedService<TokenCleanupService>();

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

app.UseHttpsRedirection();
app.UseStaticFiles();

// Security headers temporarily disabled for Safari debugging
// TODO: Re-enable after fixing Safari issue
app.Use(async (context, next) =>
{
    // Minimal headers only
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    await next();
});

// Add rate limiting
app.UseIpRateLimiting();

app.UseRouting();

app.UseCors("AllowWebClients");

app.UseAuthentication();
// Temporarily disabled for UAT OAuth debugging - session tracking interferes with OAuth flow
// app.UseSessionTracking();
app.UseAuthorization();

// Static test endpoint to debug Safari crash - bypasses all middleware
app.MapGet("/safari-test", () => Results.Content(
    "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello Safari</h1><p>If you see this, the page works.</p></body></html>",
    "text/html"));

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Seed database on startup
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        await context.Database.MigrateAsync();

        // Seed OAuth clients and test data
        var seeder = new DbSeeder(
            services,
            app.Configuration,
            services.GetRequiredService<ILogger<DbSeeder>>());
        await seeder.SeedAsync();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or seeding the database.");
    }
}

app.Run();

// Helper function to convert PostgreSQL URI format to key=value connection string format
static string NormalizePostgresConnectionString(string connectionString)
{
    try
    {
        // Parse the URI
        var uri = new Uri(connectionString);

        // Extract components
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 5432;
        var database = uri.AbsolutePath.TrimStart('/');
        var userInfo = uri.UserInfo.Split(':');
        var username = userInfo.Length > 0 ? Uri.UnescapeDataString(userInfo[0]) : "postgres";
        var password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : "";

        // Build key=value connection string
        var builder = new System.Text.StringBuilder();
        builder.Append($"Host={host};");
        builder.Append($"Port={port};");
        builder.Append($"Database={database};");
        builder.Append($"Username={username};");
        if (!string.IsNullOrEmpty(password))
        {
            builder.Append($"Password={password};");
        }

        // Add common parameters from query string if present
        var query = uri.Query;
        if (!string.IsNullOrEmpty(query))
        {
            // Remove leading '?' and parse manually
            var queryString = query.TrimStart('?');
            var pairs = queryString.Split('&');
            foreach (var pair in pairs)
            {
                var keyValue = pair.Split('=');
                if (keyValue.Length == 2)
                {
                    builder.Append($"{Uri.UnescapeDataString(keyValue[0])}={Uri.UnescapeDataString(keyValue[1])};");
                }
            }
        }

        return builder.ToString().TrimEnd(';');
    }
    catch (Exception ex)
    {
        throw new InvalidOperationException($"Failed to parse PostgreSQL URI: {ex.Message}", ex);
    }
}

// Make Program class accessible for integration tests
public partial class Program { }
