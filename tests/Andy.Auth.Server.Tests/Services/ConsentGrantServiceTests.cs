using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// Security-focused tests for <see cref="ConsentGrantService"/>, the server-side
/// state that replaced the client-forgeable <c>consent_granted=true</c> marker
/// (issue #124). Covers the create + consume lifecycle and every negative path:
/// forged/absent id, replay, expiry, and user/client/redirect/scope tampering.
/// </summary>
public class ConsentGrantServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly ConsentGrantService _service;

    private const string User = "user-1";
    private const string Client = "client-1";
    private const string Redirect = "https://app.example.com/callback";

    public ConsentGrantServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);
        _service = new ConsentGrantService(_context, Mock.Of<ILogger<ConsentGrantService>>());
    }

    public void Dispose() => _context.Dispose();

    private async Task<ConsentGrant> SeedAsync(
        IEnumerable<string>? requested = null,
        IEnumerable<string>? granted = null,
        string user = User,
        string client = Client,
        string? redirect = Redirect)
    {
        requested ??= new[] { "openid", "profile" };
        granted ??= new[] { "openid", "profile" };
        return await _service.CreateAsync(user, client, redirect, requested, granted);
    }

    // ==================== Create ====================

    [Fact]
    public async Task CreateAsync_PersistsUnconsumedShortLivedGrantWithUnguessableId()
    {
        var grant = await SeedAsync(
            requested: new[] { "openid", "profile", "email" },
            granted: new[] { "openid", "profile" });

        grant.GrantId.Should().NotBeNullOrWhiteSpace();
        grant.GrantId.Length.Should().BeGreaterThan(20); // 32 random bytes, base64url
        grant.ConsumedAt.Should().BeNull();
        grant.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        grant.ExpiresAt.Should().BeBefore(DateTime.UtcNow.Add(ConsentGrantService.DefaultLifetime).AddSeconds(5));
        grant.RequestedScopesList.Should().BeEquivalentTo(new[] { "openid", "profile", "email" });
        grant.GrantedScopesList.Should().BeEquivalentTo(new[] { "openid", "profile" });
    }

    [Fact]
    public async Task CreateAsync_GeneratesDistinctIds()
    {
        var a = await SeedAsync();
        var b = await SeedAsync();
        a.GrantId.Should().NotBe(b.GrantId);
    }

    // ==================== Consume: happy path ====================

    [Fact]
    public async Task ConsumeAsync_ValidGrant_ReturnsApprovedSubsetAndConsumes()
    {
        var grant = await SeedAsync(
            requested: new[] { "openid", "profile", "email" },
            granted: new[] { "openid", "profile" });

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect,
            new[] { "openid", "profile", "email" });

        result.Succeeded.Should().BeTrue();
        result.Status.Should().Be(ConsentGrantConsumeStatus.Success);
        // Only the approved subset is issued — email was requested but never approved.
        result.ApprovedScopes.Should().BeEquivalentTo(new[] { "openid", "profile" });
        result.ApprovedScopes.Should().NotContain("email");

        var reloaded = await _context.ConsentGrants.FindAsync(grant.Id);
        reloaded!.ConsumedAt.Should().NotBeNull();
    }

    // ==================== Consume: forged / absent id ====================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ConsumeAsync_NoConsentId_ReturnsNotFound(string? consentId)
    {
        var result = await _service.ConsumeAsync(
            consentId, User, Client, Redirect, new[] { "openid" });

        result.Succeeded.Should().BeFalse();
        result.Status.Should().Be(ConsentGrantConsumeStatus.NotFound);
    }

    [Fact]
    public async Task ConsumeAsync_ForgedConsentId_ReturnsNotFound()
    {
        // A client that fabricates a consent_id (the attack the old
        // consent_granted=true marker enabled) matches nothing server-side.
        await SeedAsync();

        var result = await _service.ConsumeAsync(
            "totally-made-up-id", User, Client, Redirect, new[] { "openid", "profile" });

        result.Succeeded.Should().BeFalse();
        result.Status.Should().Be(ConsentGrantConsumeStatus.NotFound);
    }

    // ==================== Consume: replay ====================

    [Fact]
    public async Task ConsumeAsync_SecondUse_IsRejectedAsReplay()
    {
        var grant = await SeedAsync();

        var first = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect, new[] { "openid", "profile" });
        first.Succeeded.Should().BeTrue();

        var second = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect, new[] { "openid", "profile" });

        second.Succeeded.Should().BeFalse();
        second.Status.Should().Be(ConsentGrantConsumeStatus.Replayed);
    }

    // ==================== Consume: expiry ====================

    [Fact]
    public async Task ConsumeAsync_ExpiredGrant_IsRejected()
    {
        var grant = await SeedAsync();
        // Force expiry in the past.
        grant.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await _context.SaveChangesAsync();

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect, new[] { "openid", "profile" });

        result.Succeeded.Should().BeFalse();
        result.Status.Should().Be(ConsentGrantConsumeStatus.Expired);
    }

    // ==================== Consume: tampering ====================

    [Fact]
    public async Task ConsumeAsync_DifferentUser_IsRejected()
    {
        var grant = await SeedAsync();

        var result = await _service.ConsumeAsync(
            grant.GrantId, "attacker", Client, Redirect, new[] { "openid", "profile" });

        result.Status.Should().Be(ConsentGrantConsumeStatus.BindingMismatch);

        // The grant is NOT consumed by a mismatched attempt, so the legitimate
        // user can still complete their flow.
        var reloaded = await _context.ConsentGrants.FindAsync(grant.Id);
        reloaded!.ConsumedAt.Should().BeNull();
    }

    [Fact]
    public async Task ConsumeAsync_DifferentClient_IsRejected()
    {
        var grant = await SeedAsync();

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, "other-client", Redirect, new[] { "openid", "profile" });

        result.Status.Should().Be(ConsentGrantConsumeStatus.BindingMismatch);
    }

    [Fact]
    public async Task ConsumeAsync_DifferentRedirectUri_IsRejected()
    {
        var grant = await SeedAsync();

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, Client, "https://evil.example.com/callback",
            new[] { "openid", "profile" });

        result.Status.Should().Be(ConsentGrantConsumeStatus.BindingMismatch);
    }

    [Fact]
    public async Task ConsumeAsync_ScopeEscalation_IsRejected()
    {
        // User approved [openid, profile]; the client then widens the request
        // to include "admin" on the callback. The requested set no longer
        // matches what was consented, so the grant is not honoured.
        var grant = await SeedAsync(
            requested: new[] { "openid", "profile" },
            granted: new[] { "openid", "profile" });

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect,
            new[] { "openid", "profile", "admin" });

        result.Succeeded.Should().BeFalse();
        result.Status.Should().Be(ConsentGrantConsumeStatus.BindingMismatch);
    }

    [Fact]
    public async Task ConsumeAsync_ScopeSetShrunk_IsRejected()
    {
        // Any divergence from the exact requested set the user approved against
        // forces re-consent.
        var grant = await SeedAsync(
            requested: new[] { "openid", "profile" },
            granted: new[] { "openid", "profile" });

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect, new[] { "openid" });

        result.Status.Should().Be(ConsentGrantConsumeStatus.BindingMismatch);
    }

    [Fact]
    public async Task ConsumeAsync_ScopeOrderDiffers_StillSucceeds()
    {
        // Scope matching is set-based, not order-sensitive.
        var grant = await SeedAsync(
            requested: new[] { "openid", "profile", "email" },
            granted: new[] { "openid", "profile", "email" });

        var result = await _service.ConsumeAsync(
            grant.GrantId, User, Client, Redirect,
            new[] { "email", "openid", "profile" });

        result.Succeeded.Should().BeTrue();
        result.ApprovedScopes.Should().BeEquivalentTo(new[] { "openid", "profile", "email" });
    }

    // ==================== Consume: genuine concurrency ====================

    [Fact]
    public async Task ConsumeAsync_ConcurrentReplays_ExactlyOneSucceeds()
    {
        // The single-use guarantee must hold under concurrency, not just in the
        // sequential case. This uses a real relational provider (file-backed
        // SQLite, one connection per DbContext — mirroring per-request scoping)
        // so the atomic "UPDATE ... WHERE ConsumedAt IS NULL" is exercised for
        // real. A read-then-write consume would let several racers all observe
        // ConsumedAt == null and all succeed.
        var dbFile = Path.Combine(Path.GetTempPath(), $"consent-conc-{Guid.NewGuid():N}.db");
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite($"DataSource={dbFile}")
            .Options;

        try
        {
            string grantId;
            using (var ctx = new ApplicationDbContext(options))
            {
                await ctx.Database.EnsureCreatedAsync();

                // Satisfy the ConsentGrant -> AspNetUsers foreign key (SQLite
                // enforces FKs; the in-memory provider does not).
                ctx.Users.Add(new ApplicationUser { Id = User, UserName = User, Email = "u@example.com" });
                await ctx.SaveChangesAsync();

                var seedService = new ConsentGrantService(ctx, Mock.Of<ILogger<ConsentGrantService>>());
                var grant = await seedService.CreateAsync(
                    User, Client, Redirect,
                    new[] { "openid", "profile" }, new[] { "openid", "profile" });
                grantId = grant.GrantId;
            }

            const int concurrency = 16;
            var tasks = Enumerable.Range(0, concurrency).Select(_ => Task.Run(async () =>
            {
                // Each racer gets its own DbContext + connection, as in production.
                using var ctx = new ApplicationDbContext(options);
                var service = new ConsentGrantService(ctx, Mock.Of<ILogger<ConsentGrantService>>());
                var result = await service.ConsumeAsync(
                    grantId, User, Client, Redirect, new[] { "openid", "profile" });
                return result.Succeeded;
            })).ToArray();

            var results = await Task.WhenAll(tasks);

            results.Count(ok => ok).Should().Be(
                1, "exactly one concurrent replay may consume a single-use grant");

            using (var verify = new ApplicationDbContext(options))
            {
                var g = await verify.ConsentGrants.SingleAsync(x => x.GrantId == grantId);
                g.ConsumedAt.Should().NotBeNull();
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbFile))
            {
                File.Delete(dbFile);
            }
        }
    }
}
