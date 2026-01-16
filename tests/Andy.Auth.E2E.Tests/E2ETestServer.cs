using Andy.Auth.Server.Data;
using Andy.Auth.Server.Middleware;
using Andy.Auth.Server.Services;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// Manages a test server for E2E tests with Playwright.
/// Creates a real HTTP server that browsers can connect to.
/// </summary>
public class E2ETestServer : IAsyncDisposable
{
    private WebApplication? _app;
    private readonly string _databaseName = Guid.NewGuid().ToString();

    public string ServerAddress { get; private set; } = string.Empty;

    public async Task StartAsync()
    {
        if (_app != null) return;

        // Find the content root (Andy.Auth.Server project directory)
        var contentRoot = FindContentRoot();

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Development",
            ContentRootPath = contentRoot,
            WebRootPath = Path.Combine(contentRoot, "wwwroot")
        });

        // Use a random available port
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        // Configure services - add controllers and views from the main application
        builder.Services.AddControllersWithViews()
            .AddApplicationPart(typeof(Program).Assembly);

        // Configure rate limiting
        builder.Services.AddMemoryCache();
        builder.Services.Configure<IpRateLimitOptions>(options => { });
        builder.Services.AddInMemoryRateLimiting();
        builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

        // Use in-memory database for testing
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseInMemoryDatabase(_databaseName);
            options.UseOpenIddict();
        });

        // Configure ASP.NET Core Identity
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = true;
            options.Password.RequireLowercase = true;
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = false;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

        // Configure cookie authentication
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/Account/Login";
            options.AccessDeniedPath = "/Account/AccessDenied";
            options.LogoutPath = "/Account/Logout";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = SameSiteMode.Lax;
        });

        // Register custom services
        builder.Services.AddScoped<IAuditService, AuditService>();
        builder.Services.AddScoped<SessionService>();

        // Configure OpenIddict
        builder.Services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetEndSessionEndpointUris("connect/logout")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetIntrospectionEndpointUris("connect/introspect");

                options.AllowAuthorizationCodeFlow()
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow();

                options.RegisterScopes("openid", "profile", "email", "offline_access");

                // Use ephemeral keys for testing (in-memory, no keychain access needed)
                options.AddEphemeralEncryptionKey()
                    .AddEphemeralSigningKey();

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        // Add authorization policies
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
        });

        _app = builder.Build();

        // Configure the HTTP request pipeline
        _app.UseStaticFiles();
        _app.UseRouting();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.UseMiddleware<SessionTrackingMiddleware>();
        _app.MapControllers();
        _app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        // Start the application
        await _app.StartAsync();

        // Get the server address
        var addresses = _app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>();
        ServerAddress = addresses?.Addresses.First() ?? throw new Exception("No server address");

        // Seed test data
        await SeedTestDataAsync();
    }

    private async Task SeedTestDataAsync()
    {
        using var scope = _app!.Services.CreateScope();
        var services = scope.ServiceProvider;

        var db = services.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureCreatedAsync();

        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        // Ensure roles exist
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
        }
        if (!await roleManager.RoleExistsAsync("User"))
        {
            await roleManager.CreateAsync(new IdentityRole("User"));
        }

        // Create test admin user
        var adminEmail = "admin@test.com";
        var admin = await userManager.FindByEmailAsync(adminEmail);
        if (admin == null)
        {
            admin = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                FullName = "Test Admin",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };
            var result = await userManager.CreateAsync(admin, "Admin123!");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(admin, "Admin");
            }
        }

        // Create test regular user
        var userEmail = "user@test.com";
        var user = await userManager.FindByEmailAsync(userEmail);
        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = userEmail,
                Email = userEmail,
                EmailConfirmed = true,
                FullName = "Test User",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };
            var result = await userManager.CreateAsync(user, "User123!");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(user, "User");
            }
        }

        // Create user that must change password
        var mustChangeEmail = "mustchange@test.com";
        var mustChangeUser = await userManager.FindByEmailAsync(mustChangeEmail);
        if (mustChangeUser == null)
        {
            mustChangeUser = new ApplicationUser
            {
                UserName = mustChangeEmail,
                Email = mustChangeEmail,
                EmailConfirmed = true,
                FullName = "Must Change Password User",
                IsActive = true,
                MustChangePassword = true,
                CreatedAt = DateTime.UtcNow
            };
            var result = await userManager.CreateAsync(mustChangeUser, "TempPass123!");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(mustChangeUser, "User");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_app != null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private static string FindContentRoot()
    {
        // Find the Andy.Auth.Server project directory
        var currentDir = Directory.GetCurrentDirectory();
        var searchDir = currentDir;

        // Walk up to find the solution directory
        while (!string.IsNullOrEmpty(searchDir) && !File.Exists(Path.Combine(searchDir, "andy-auth.sln")))
        {
            searchDir = Directory.GetParent(searchDir)?.FullName;
        }

        if (string.IsNullOrEmpty(searchDir))
        {
            throw new Exception($"Could not find solution directory from {currentDir}");
        }

        var serverPath = Path.Combine(searchDir, "src", "Andy.Auth.Server");
        if (!Directory.Exists(serverPath))
        {
            throw new Exception($"Server project not found at {serverPath}");
        }

        return serverPath;
    }
}
