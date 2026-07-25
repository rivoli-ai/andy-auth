using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// #121 — atomic, concurrency-safe consumption of DCR initial access tokens.
///
/// These tests run against a real file-backed SQLite database (not the EF
/// in-memory provider) so that <see cref="DcrService.TryConsumeInitialAccessTokenAsync"/>
/// exercises its production relational path — the single conditional
/// <c>UPDATE ... WHERE still-valid</c> whose affected-row count is the arbiter.
/// A shared file lets multiple independent DbContexts (each its own connection)
/// contend for the same token concurrently, which is the whole point of the
/// invariant.
/// </summary>
public sealed class DcrAtomicConsumeTests : IDisposable
{
    private readonly string _dbPath;
    private readonly string _connectionString;
    private readonly DcrSettings _settings = new()
    {
        Enabled = true,
        AllowedGrantTypes = new List<string> { "authorization_code" },
        AllowedScopes = new List<string> { "openid" }
    };

    public DcrAtomicConsumeTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"dcr-atomic-{Guid.NewGuid():N}.sqlite");
        // Default Timeout=30 => Microsoft.Data.Sqlite waits (busy_timeout) rather
        // than throwing SQLITE_BUSY when concurrent writers contend, so parallel
        // consume attempts serialize cleanly at the database.
        _connectionString = $"Data Source={_dbPath};Default Timeout=30";

        using var context = CreateContext();
        context.Database.EnsureCreated();
    }

    public void Dispose()
    {
        // Drop any pooled connections so the file can be deleted on all OSes.
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }

    private ApplicationDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite(_connectionString)
            .Options;
        var context = new ApplicationDbContext(options);
        context.Database.SetCommandTimeout(30);
        return context;
    }

    private DcrService CreateService(ApplicationDbContext context) =>
        new(context, Options.Create(_settings), NullLogger<DcrService>.Instance);

    private async Task<int> SeedTokenAsync(bool isMultiUse, int? maxUses, Action<InitialAccessToken>? mutate = null)
    {
        using var context = CreateContext();
        var token = new InitialAccessToken
        {
            Name = "concurrency-token",
            TokenHash = Guid.NewGuid().ToString("N"),
            CreatedById = "admin",
            CreatedByEmail = "admin@test.com",
            CreatedAt = DateTime.UtcNow,
            IsMultiUse = isMultiUse,
            MaxUses = maxUses
        };
        mutate?.Invoke(token);
        context.InitialAccessTokens.Add(token);
        await context.SaveChangesAsync();
        return token.Id;
    }

    private async Task<int> GetUseCountAsync(int tokenId)
    {
        using var context = CreateContext();
        var token = await context.InitialAccessTokens.FindAsync(tokenId);
        return token!.UseCount;
    }

    private async Task<bool[]> ConsumeConcurrentlyAsync(int tokenId, int attempts)
    {
        // Pre-create all contexts, then release them together to maximise the
        // window in which they actually contend.
        var gate = new TaskCompletionSource();
        var tasks = Enumerable.Range(0, attempts).Select(async _ =>
        {
            await gate.Task;
            using var context = CreateContext();
            var service = CreateService(context);
            return await service.TryConsumeInitialAccessTokenAsync(tokenId);
        }).ToArray();

        gate.SetResult();
        return await Task.WhenAll(tasks);
    }

    [Fact]
    public async Task SingleUseToken_UnderConcurrency_SucceedsExactlyOnce()
    {
        var tokenId = await SeedTokenAsync(isMultiUse: false, maxUses: null);

        var results = await ConsumeConcurrentlyAsync(tokenId, attempts: 25);

        results.Count(r => r).Should().Be(1, "a single-use IAT may be consumed exactly once");
        (await GetUseCountAsync(tokenId)).Should().Be(1);
    }

    [Fact]
    public async Task MaxUseToken_UnderConcurrency_NeverExceedsConfiguredCount()
    {
        const int maxUses = 5;
        var tokenId = await SeedTokenAsync(isMultiUse: true, maxUses: maxUses);

        var results = await ConsumeConcurrentlyAsync(tokenId, attempts: 25);

        results.Count(r => r).Should().Be(maxUses, "a max-use IAT cannot be consumed more than MaxUses times");
        (await GetUseCountAsync(tokenId)).Should().Be(maxUses);
    }

    [Fact]
    public async Task Consume_RevokedToken_FailsAtomically_AndDoesNotIncrement()
    {
        var tokenId = await SeedTokenAsync(isMultiUse: true, maxUses: 10, mutate: t =>
        {
            t.IsRevoked = true;
            t.RevokedAt = DateTime.UtcNow;
        });

        using var context = CreateContext();
        var service = CreateService(context);

        (await service.TryConsumeInitialAccessTokenAsync(tokenId)).Should().BeFalse();
        (await GetUseCountAsync(tokenId)).Should().Be(0, "revocation is checked in the same atomic UPDATE");
    }

    [Fact]
    public async Task Consume_ExpiredToken_FailsAtomically_AndDoesNotIncrement()
    {
        var tokenId = await SeedTokenAsync(isMultiUse: true, maxUses: 10, mutate: t =>
            t.ExpiresAt = DateTime.UtcNow.AddMinutes(-5));

        using var context = CreateContext();
        var service = CreateService(context);

        (await service.TryConsumeInitialAccessTokenAsync(tokenId)).Should().BeFalse();
        (await GetUseCountAsync(tokenId)).Should().Be(0, "expiry is checked in the same atomic UPDATE");
    }

    [Fact]
    public async Task Consume_SingleUseToken_SecondSequentialAttemptFails()
    {
        var tokenId = await SeedTokenAsync(isMultiUse: false, maxUses: null);

        using (var context = CreateContext())
        {
            (await CreateService(context).TryConsumeInitialAccessTokenAsync(tokenId)).Should().BeTrue();
        }

        using (var context = CreateContext())
        {
            (await CreateService(context).TryConsumeInitialAccessTokenAsync(tokenId)).Should().BeFalse();
        }

        (await GetUseCountAsync(tokenId)).Should().Be(1);
    }
}
