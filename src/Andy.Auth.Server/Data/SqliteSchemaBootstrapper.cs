using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Heals additive schema drift on the embedded SQLite database.
///
/// Background: andy-auth's SQLite path uses
/// <see cref="Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade.EnsureCreatedAsync(CancellationToken)"/>,
/// which creates the schema from the live EF model on a fresh DB but is a
/// no-op once any table exists. Migrations are not applied on the SQLite
/// path, so a user whose DB was created by an older binary is stuck on
/// whatever schema EnsureCreated produced back then. When a new entity
/// property or entity set lands, every query that touches it fails with
/// <c>SQLite Error 1: 'no such column'</c> / <c>'no such table'</c>.
///
/// This bootstrapper closes that gap. After EnsureCreatedAsync has had a
/// chance to run, it compares the live EF model (including the ASP.NET
/// Identity and OpenIddict entity sets — they are regular EF entities)
/// against the actual SQLite schema and:
///   - creates any table the model declares that the DB lacks, using the
///     exact DDL <see cref="Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade.GenerateCreateScript"/>
///     would emit (never hand-written SQL), plus that table's indexes;
///   - adds any column the model declares that an existing table lacks,
///     for nullable / defaulted / converter-backed columns only.
///
/// Only additive changes are performed — we never drop, rename, or alter,
/// because those risk data loss and the migrations system is the right
/// tool for them. On a completely empty DB (zero user tables) it no-ops:
/// that is EnsureCreated's job.
/// </summary>
public static class SqliteSchemaBootstrapper
{
    /// <summary>
    /// Heals additive schema drift: first creates any tables the EF model
    /// declares that the live SQLite DB lacks (using EnsureCreated's own
    /// generated DDL), then adds any missing columns on existing tables.
    /// Returns the number of healed objects (tables + columns). No-ops on
    /// non-SQLite providers and on a completely empty database.
    /// </summary>
    public static async Task<int> HealAsync(
        ApplicationDbContext db,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        if (!db.Database.IsSqlite()) return 0;

        var conn = db.Database.GetDbConnection();
        if (conn.State != System.Data.ConnectionState.Open)
        {
            await conn.OpenAsync(cancellationToken);
        }

        var existingTables = await ReadTableNamesAsync(conn, cancellationToken);
        if (existingTables.Count == 0)
        {
            // Fresh DB — EnsureCreated materialises the full schema; nothing to heal.
            return 0;
        }

        int healed = 0;
        healed += await HealMissingTablesAsync(db, conn, existingTables, logger, cancellationToken);
        healed += await HealMissingColumnsAsync(db, conn, logger, cancellationToken);

        if (healed > 0)
        {
            logger.LogWarning(
                "andy-auth SQLite schema heal complete: {Healed} object(s) added.",
                healed);
        }
        return healed;
    }

    private static async Task<int> HealMissingTablesAsync(
        ApplicationDbContext db,
        System.Data.Common.DbConnection conn,
        HashSet<string> existingTables,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        // Which model tables are absent from the live DB?
        var missing = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entityType in db.Model.GetEntityTypes())
        {
            var tableName = entityType.GetTableName();
            if (string.IsNullOrEmpty(tableName)) continue;
            if (!IsSafeIdentifier(tableName)) continue;
            if (!existingTables.Contains(tableName)) missing.Add(tableName);
        }
        if (missing.Count == 0) return 0;

        // EnsureCreated's own DDL — statements separated by ";" at line end.
        var script = db.Database.GenerateCreateScript();
        var statements = SplitSqlStatements(script);

        int created = 0;
        foreach (var table in missing)
        {
            // CREATE TABLE first, then its indexes.
            var createTable = statements.FirstOrDefault(s =>
                s.StartsWith($"CREATE TABLE \"{table}\"", StringComparison.Ordinal));
            if (createTable is null)
            {
                logger.LogWarning(
                    "andy-auth SQLite schema heal: model table {Table} missing from DB but no CREATE TABLE found in generated script; skipping.",
                    table);
                continue;
            }

            logger.LogWarning(
                "andy-auth SQLite schema heal: creating missing table {Table}.",
                table);
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = createTable;
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            created++;

            foreach (var index in statements.Where(s =>
                         s.StartsWith("CREATE INDEX", StringComparison.Ordinal) ||
                         s.StartsWith("CREATE UNIQUE INDEX", StringComparison.Ordinal)))
            {
                if (!index.Contains($" ON \"{table}\" ", StringComparison.Ordinal)) continue;
                using var cmd = conn.CreateCommand();
                cmd.CommandText = index;
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        return created;
    }

    private static async Task<int> HealMissingColumnsAsync(
        ApplicationDbContext db,
        System.Data.Common.DbConnection conn,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        int healed = 0;

        foreach (var entityType in db.Model.GetEntityTypes())
        {
            var tableName = entityType.GetTableName();
            if (string.IsNullOrEmpty(tableName)) continue;
            if (!IsSafeIdentifier(tableName)) continue;

            var actualColumns = await ReadColumnsAsync(conn, tableName, cancellationToken);
            if (actualColumns.Count == 0)
            {
                // Table not created yet — nothing to compare against.
                continue;
            }

            var storeObject = StoreObjectIdentifier.Table(tableName, entityType.GetSchema());

            foreach (var property in entityType.GetProperties())
            {
                var columnName = property.GetColumnName(storeObject);
                if (string.IsNullOrEmpty(columnName)) continue;
                if (actualColumns.Contains(columnName)) continue;
                if (!IsSafeIdentifier(columnName)) continue;

                // Only auto-add columns that are safe to add to a
                // populated table: must be nullable OR have a default
                // value OR be backed by a value converter that
                // gracefully handles missing data on read. Anything
                // else needs human attention (a migration).
                var isNullable = property.IsColumnNullable();
                var defaultSql = property.GetDefaultValueSql(storeObject);
                var defaultValue = property.GetDefaultValue(storeObject);
                var hasValueConverter = property.GetValueConverter() is not null;
                if (!isNullable && defaultSql is null && defaultValue is null && !hasValueConverter)
                {
                    logger.LogWarning(
                        "andy-auth SQLite schema heal: refusing to add non-nullable column {Table}.{Column} without default.",
                        tableName,
                        columnName);
                    continue;
                }

                var columnType = ResolveSqliteColumnType(property);
                // Converter-backed non-nullable properties get added as
                // nullable on the SQLite path — the converter handles
                // null → safe default at read time. Plain non-nullable
                // columns keep their NOT NULL + default.
                var addAsNullable = isNullable || (hasValueConverter && defaultSql is null && defaultValue is null);
                var nullClause = addAsNullable ? "NULL" : "NOT NULL";
                var defaultClause = defaultSql is not null
                    ? $" DEFAULT ({defaultSql})"
                    : (defaultValue is not null ? $" DEFAULT {FormatDefaultLiteral(defaultValue)}" : "");

                var alterSql = $"ALTER TABLE \"{tableName}\" ADD COLUMN \"{columnName}\" {columnType} {nullClause}{defaultClause};";

                logger.LogWarning(
                    "andy-auth SQLite schema heal: adding missing column {Table}.{Column} (\"{Sql}\").",
                    tableName,
                    columnName,
                    alterSql);

                using var cmd = conn.CreateCommand();
                cmd.CommandText = alterSql;
                await cmd.ExecuteNonQueryAsync(cancellationToken);
                healed++;
            }
        }

        return healed;
    }

    private static async Task<HashSet<string>> ReadTableNamesAsync(
        System.Data.Common.DbConnection conn,
        CancellationToken cancellationToken)
    {
        var tables = new HashSet<string>(StringComparer.Ordinal);
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name <> '__EFMigrationsHistory';";
        using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            tables.Add(reader.GetString(0));
        }
        return tables;
    }

    private static async Task<HashSet<string>> ReadColumnsAsync(
        System.Data.Common.DbConnection conn,
        string tableName,
        CancellationToken cancellationToken)
    {
        var columns = new HashSet<string>(StringComparer.Ordinal);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info(\"{tableName}\");";
        using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // PRAGMA table_info columns: cid (0), name (1), type (2), ...
            columns.Add(reader.GetString(1));
        }
        return columns;
    }

    private static string ResolveSqliteColumnType(IProperty property)
    {
        // Prefer the explicit relational type mapping (what EF would
        // emit when creating the schema). Falls back to TEXT as the
        // last-resort SQLite-affinity-safe default.
        var typeMapping = property.GetRelationalTypeMapping();
        var storeType = typeMapping?.StoreType;
        if (!string.IsNullOrEmpty(storeType)) return storeType;

        var configured = property.GetColumnType();
        return !string.IsNullOrEmpty(configured) ? configured : "TEXT";
    }

    private static string FormatDefaultLiteral(object value)
    {
        return value switch
        {
            bool b => b ? "1" : "0",
            string s => $"'{s.Replace("'", "''")}'",
            null => "NULL",
            _ => value.ToString() ?? "NULL"
        };
    }

    private static List<string> SplitSqlStatements(string script)
    {
        // EF's SQLite create script separates statements with ";" followed
        // by a newline. No procedural blocks exist on SQLite, so this split
        // is unambiguous.
        return script
            .Split([";\r\n", ";\n"], StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();
    }

    private static bool IsSafeIdentifier(string identifier)
    {
        if (string.IsNullOrEmpty(identifier)) return false;
        foreach (var c in identifier)
        {
            if (!(char.IsLetterOrDigit(c) || c == '_')) return false;
        }
        return true;
    }
}
