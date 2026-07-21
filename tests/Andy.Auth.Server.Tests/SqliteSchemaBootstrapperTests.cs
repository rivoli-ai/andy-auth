using Andy.Auth.Server.Data;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Tests for <see cref="SqliteSchemaBootstrapper"/> — the additive schema
/// drift heal that runs after EnsureCreatedAsync on the SQLite path.
/// </summary>
public class SqliteSchemaBootstrapperTests : IDisposable
{
    private readonly string _dbPath;
    private readonly RecordingLogger _logger = new();

    public SqliteSchemaBootstrapperTests()
    {
        _dbPath = Path.Combine(
            Path.GetTempPath(),
            $"andy-auth-schema-heal-{Guid.NewGuid():N}.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath))
        {
            File.Delete(_dbPath);
        }
        GC.SuppressFinalize(this);
    }

    private ApplicationDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite($"Data Source={_dbPath}")
            .Options;
        return new ApplicationDbContext(options);
    }

    private async Task ExecuteRawAsync(string sql)
    {
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<HashSet<string>> ReadColumnsAsync(string table)
    {
        var columns = new HashSet<string>(StringComparer.Ordinal);
        await using var conn = new SqliteConnection($"Data Source={_dbPath}");
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info(\"{table}\");";
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            columns.Add(reader.GetString(1));
        }
        return columns;
    }

    [Fact]
    public async Task Heal_RestoresDroppedNullableColumn_AndTableIsQueryable()
    {
        // Arrange: full schema, then simulate an old-binary DB by dropping a
        // nullable column the current model declares.
        await using (var setup = CreateContext())
        {
            await setup.Database.EnsureCreatedAsync();
        }
        SqliteConnection.ClearAllPools();
        await ExecuteRawAsync("ALTER TABLE \"UserSessions\" DROP COLUMN \"Location\";");
        (await ReadColumnsAsync("UserSessions")).Should().NotContain("Location");

        // Act
        int healed;
        await using (var db = CreateContext())
        {
            healed = await SqliteSchemaBootstrapper.HealAsync(db, _logger);
        }

        // Assert: column restored and the entity is queryable end-to-end.
        healed.Should().Be(1);
        (await ReadColumnsAsync("UserSessions")).Should().Contain("Location");
        await using (var db = CreateContext())
        {
            // UserSessions has an FK to AspNetUsers — satisfy it first.
            db.Users.Add(new ApplicationUser
            {
                Id = "user-1",
                UserName = "test@andy.local",
                Email = "test@andy.local",
            });
            db.UserSessions.Add(new UserSession
            {
                UserId = "user-1",
                SessionId = "session-1",
                Location = "Paris, FR",
            });
            await db.SaveChangesAsync();
        }
        await using (var verify = CreateContext())
        {
            var session = await verify.UserSessions.SingleAsync(s => s.SessionId == "session-1");
            session.Location.Should().Be("Paris, FR");
        }
    }

    [Fact]
    public async Task Heal_RecreatesDroppedLeafTable_WithModelColumns()
    {
        await using (var setup = CreateContext())
        {
            await setup.Database.EnsureCreatedAsync();
        }
        SqliteConnection.ClearAllPools();
        await ExecuteRawAsync("DROP TABLE \"AuditLogs\";");
        (await ReadColumnsAsync("AuditLogs")).Should().BeEmpty();

        int healed;
        await using (var db = CreateContext())
        {
            healed = await SqliteSchemaBootstrapper.HealAsync(db, _logger);
        }

        healed.Should().Be(1);
        var columns = await ReadColumnsAsync("AuditLogs");
        columns.Should().Contain(
            ["Id", "Action", "PerformedById", "PerformedByEmail", "TargetUserId", "TargetUserEmail", "Details", "PerformedAt", "IpAddress"]);

        // The recreated table must be usable through EF.
        await using (var db = CreateContext())
        {
            db.AuditLogs.Add(new AuditLog
            {
                Action = "UserSuspended",
                PerformedById = "admin-1",
                PerformedByEmail = "admin@andy.local",
            });
            await db.SaveChangesAsync();
        }
        await using (var verify = CreateContext())
        {
            (await verify.AuditLogs.CountAsync()).Should().Be(1);
        }
    }

    [Fact]
    public async Task Heal_RecreatesDroppedOpenIddictTable()
    {
        // The model includes the OpenIddict entity sets; the heal must cover
        // them like any other entity (GenerateCreateScript emits their DDL).
        await using (var setup = CreateContext())
        {
            await setup.Database.EnsureCreatedAsync();
        }
        SqliteConnection.ClearAllPools();
        await ExecuteRawAsync("DROP TABLE \"OpenIddictScopes\";");

        int healed;
        await using (var db = CreateContext())
        {
            healed = await SqliteSchemaBootstrapper.HealAsync(db, _logger);
        }

        healed.Should().Be(1);
        (await ReadColumnsAsync("OpenIddictScopes")).Should().Contain(["Id", "Name"]);
    }

    [Fact]
    public async Task Heal_OnFreshEmptyDatabase_IsNoOp()
    {
        // No EnsureCreated — zero user tables. Healing must leave the DB to
        // EnsureCreated and report nothing healed.
        int healed;
        await using (var db = CreateContext())
        {
            healed = await SqliteSchemaBootstrapper.HealAsync(db, _logger);
        }

        healed.Should().Be(0);
        await using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
        {
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText =
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';";
            var count = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            count.Should().Be(0);
        }
    }

    [Fact]
    public async Task Heal_RefusesNonNullableColumnWithoutDefault_AndWarns()
    {
        // AuditLogs.Action is non-nullable with no default and no value
        // converter — the heal must refuse it and log a warning instead of
        // adding a column that would break existing rows.
        await using (var setup = CreateContext())
        {
            await setup.Database.EnsureCreatedAsync();
        }
        SqliteConnection.ClearAllPools();
        await ExecuteRawAsync("ALTER TABLE \"AuditLogs\" DROP COLUMN \"Action\";");

        int healed;
        await using (var db = CreateContext())
        {
            healed = await SqliteSchemaBootstrapper.HealAsync(db, _logger);
        }

        healed.Should().Be(0);
        (await ReadColumnsAsync("AuditLogs")).Should().NotContain("Action");
        _logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("refusing to add non-nullable column") &&
            e.Message.Contains("AuditLogs") &&
            e.Message.Contains("Action"));
    }

    /// <summary>
    /// Minimal in-memory logger capturing level + rendered message.
    /// </summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
