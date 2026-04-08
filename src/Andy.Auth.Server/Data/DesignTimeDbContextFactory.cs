using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Factory for creating <see cref="ApplicationDbContext"/> instances at design
/// time (used by <c>dotnet ef</c> migrations tooling).
///
/// Honours the same <c>Database__Provider</c> environment variable as the
/// runtime so a developer can generate migrations against either provider:
///
/// <code>
/// # PostgreSQL (default for legacy migrations)
/// dotnet ef migrations add MyMigration --output-dir Migrations
///
/// # SQLite (G2.1, future)
/// Database__Provider=Sqlite ConnectionStrings__Sqlite="Data Source=design.sqlite" \
///     dotnet ef migrations add MyMigration --output-dir Migrations.Sqlite
/// </code>
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var provider = DatabaseProviderExtensions.GetDatabaseProvider(configuration);

        // Design-time fallback: if no connection string is configured, use a
        // sensible per-provider default so the tooling never has to be told
        // about a real database.
        var connectionString = provider switch
        {
            DatabaseProvider.Sqlite =>
                configuration.GetConnectionString("Sqlite")
                ?? configuration.GetConnectionString("DefaultConnection")
                ?? "Data Source=andy-auth-design.sqlite",
            DatabaseProvider.PostgreSql =>
                configuration.GetConnectionString("DefaultConnection")
                ?? "Host=localhost;Database=andy_auth_dev;Username=postgres;Password=postgres",
            _ => throw new InvalidOperationException($"Unsupported provider: {provider}")
        };

        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
        DatabaseProviderExtensions.ConfigureDbContext(optionsBuilder, provider, connectionString);

        return new ApplicationDbContext(optionsBuilder.Options);
    }
}
