using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// Spins up a real OpenIddict core + file-backed SQLite stack so the DCR
/// registration path can be exercised with genuine transactions. OpenIddict's
/// application manager writes through the same <see cref="ApplicationDbContext"/>
/// registered here, which is exactly the sharing the atomic-registration fix
/// (#120) relies on.
/// </summary>
internal sealed class DcrOpenIddictSqliteHarness : IDisposable
{
    private readonly ServiceProvider _rootProvider;
    private readonly string _dbPath;
    private readonly string _connectionString;

    public DcrOpenIddictSqliteHarness()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"dcr-oidc-{Guid.NewGuid():N}.sqlite");
        _connectionString = $"Data Source={_dbPath};Default Timeout=30";

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(_connectionString));
        services.AddOpenIddict()
            .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>());

        _rootProvider = services.BuildServiceProvider();

        using var scope = _rootProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        context.Database.EnsureCreated();
    }

    public DcrSettings Settings { get; } = new()
    {
        Enabled = true,
        RequireInitialAccessToken = false,
        RequireAdminApproval = false,
        AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
        AllowedScopes = new List<string> { "openid", "profile", "email" },
        ClientSecretLifetime = TimeSpan.FromDays(365),
        AllowLocalhostRedirectUris = true,
        AllowHttpLocalhostRedirectUris = true
    };

    /// <summary>
    /// Creates an isolated DI scope. Everything in it (context, OpenIddict
    /// managers, DcrService) shares one ApplicationDbContext.
    /// </summary>
    public Operation NewOperation(
        Func<ApplicationDbContext, IOptions<DcrSettings>, DcrService>? dcrServiceFactory = null,
        IOpenIddictApplicationManager? applicationManagerOverride = null,
        string environmentName = "Development")
    {
        var scope = _rootProvider.CreateScope();
        var sp = scope.ServiceProvider;
        var context = sp.GetRequiredService<ApplicationDbContext>();
        context.Database.SetCommandTimeout(30);

        var options = Options.Create(Settings);
        var dcrService = dcrServiceFactory != null
            ? dcrServiceFactory(context, options)
            : new DcrService(context, options, NullLogger<DcrService>.Instance);

        var applicationManager = applicationManagerOverride
            ?? sp.GetRequiredService<IOpenIddictApplicationManager>();
        var tokenManager = sp.GetRequiredService<IOpenIddictTokenManager>();

        var controller = new DynamicClientRegistrationController(
            dcrService,
            options,
            applicationManager,
            tokenManager,
            context,
            NullLogger<DynamicClientRegistrationController>.Instance,
            new ConfigurationBuilder().Build(),
            new TestHostEnvironment { EnvironmentName = environmentName });

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Scheme = "https";
        httpContext.Request.Host = new HostString("auth.example.com");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        return new Operation(scope, context, dcrService, applicationManager, controller);
    }

    /// <summary>Fresh scope+context for assertions, unaffected by tracking.</summary>
    public IServiceScope NewVerificationScope() => _rootProvider.CreateScope();

    public void Dispose()
    {
        _rootProvider.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }

    internal sealed class Operation : IDisposable
    {
        private readonly IServiceScope _scope;

        public Operation(
            IServiceScope scope,
            ApplicationDbContext context,
            DcrService dcrService,
            IOpenIddictApplicationManager applicationManager,
            DynamicClientRegistrationController controller)
        {
            _scope = scope;
            Context = context;
            DcrService = dcrService;
            ApplicationManager = applicationManager;
            Controller = controller;
        }

        public ApplicationDbContext Context { get; }
        public DcrService DcrService { get; }
        public IOpenIddictApplicationManager ApplicationManager { get; }
        public DynamicClientRegistrationController Controller { get; }

        public void SetBearer(string token) =>
            Controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {token}";

        public void Dispose() => _scope.Dispose();
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Andy.Auth.Server.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; }
            = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
