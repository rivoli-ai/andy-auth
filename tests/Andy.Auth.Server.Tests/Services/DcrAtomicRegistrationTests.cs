using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models.Dcr;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// #120 — DCR registration is committed as one logical transaction and partial
/// failures leave no orphaned application/token/metadata, plus the orphan
/// reconciliation sweep. Runs against real OpenIddict core + SQLite so the
/// transaction semantics are genuine.
/// </summary>
public sealed class DcrAtomicRegistrationTests : IDisposable
{
    private readonly DcrOpenIddictSqliteHarness _harness = new();

    public void Dispose() => _harness.Dispose();

    private static ClientRegistrationRequest ValidRequest(string? name = null) => new()
    {
        ClientName = name ?? "Test App",
        RedirectUris = new List<string> { "https://example.com/callback" },
        GrantTypes = new List<string> { "authorization_code" },
        TokenEndpointAuthMethod = "client_secret_basic"
    };

    private async Task<(int Id, string PlainText)> SeedInitialAccessTokenAsync(bool isMultiUse = false, int? maxUses = null)
    {
        using var scope = _harness.NewVerificationScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var service = new DcrService(context, Options.Create(_harness.Settings), NullLogger<DcrService>.Instance);
        var (entity, plainText) = await service.CreateInitialAccessTokenAsync(
            "seed", "admin", "admin@test.com", isMultiUse: isMultiUse, maxUses: maxUses);
        return (entity.Id, plainText);
    }

    private async Task<int> CountClientsAsync() =>
        (await ReadAsync(c => c.DynamicClientRegistrations.CountAsync()));

    private async Task<int> CountRegistrationTokensAsync() =>
        (await ReadAsync(c => c.RegistrationAccessTokens.CountAsync()));

    private async Task<int> CountRegistrationAuditsAsync() =>
        (await ReadAsync(c => c.AuditLogs.CountAsync(a => a.Action == "DcrClientRegistered")));

    private async Task<int> IatUseCountAsync(int id) =>
        (await ReadAsync(c => c.InitialAccessTokens.Where(t => t.Id == id).Select(t => t.UseCount).FirstAsync()));

    private async Task<T> ReadAsync<T>(Func<ApplicationDbContext, Task<T>> query)
    {
        using var scope = _harness.NewVerificationScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        return await query(context);
    }

    private async Task<bool> ApplicationExistsAsync(string clientId)
    {
        using var scope = _harness.NewVerificationScope();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        return await appManager.FindByClientIdAsync(clientId) != null;
    }

    // ==================== Happy path — everything commits ====================

    [Fact]
    public async Task Register_Success_CommitsApplicationTokenMetadataAndAudit()
    {
        string clientId;
        using (var op = _harness.NewOperation())
        {
            var result = await op.Controller.Register(ValidRequest());
            var objectResult = result.Should().BeOfType<ObjectResult>().Subject;
            objectResult.StatusCode.Should().Be(201);
            clientId = objectResult.Value.Should().BeOfType<ClientRegistrationResponse>().Subject.ClientId;
        }

        (await ApplicationExistsAsync(clientId)).Should().BeTrue();
        (await CountClientsAsync()).Should().Be(1);
        (await CountRegistrationTokensAsync()).Should().Be(1);
        (await CountRegistrationAuditsAsync()).Should().Be(1);
    }

    // ==================== Fault injection after each persistence step ====================

    [Fact]
    public async Task Register_FailsBeforeApplicationCreate_RollsBackIatConsumption()
    {
        _harness.Settings.RequireInitialAccessToken = true;
        var (iatId, iatToken) = await SeedInitialAccessTokenAsync(isMultiUse: false);

        // Application manager whose CreateAsync throws AFTER the IAT has been
        // consumed inside the transaction.
        var throwingAppManager = new Mock<IOpenIddictApplicationManager>();
        throwingAppManager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);
        throwingAppManager.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("injected: application create"));

        using (var op = _harness.NewOperation(applicationManagerOverride: throwingAppManager.Object))
        {
            op.SetBearer(iatToken);
            var result = await op.Controller.Register(ValidRequest());
            result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(500);
        }

        (await IatUseCountAsync(iatId)).Should().Be(0, "the consumption must roll back with the failed registration");
        (await CountClientsAsync()).Should().Be(0);
        (await CountRegistrationTokensAsync()).Should().Be(0);
        (await CountRegistrationAuditsAsync()).Should().Be(0);
    }

    [Fact]
    public async Task Register_FailsAfterApplicationCreate_BeforeRat_LeavesNoOrphan()
    {
        await AssertRollbackWhenDcrStepThrows(ThrowingDcrService.Step.Rat);
    }

    [Fact]
    public async Task Register_FailsAfterRat_BeforeMetadata_LeavesNoOrphan()
    {
        await AssertRollbackWhenDcrStepThrows(ThrowingDcrService.Step.Metadata);
    }

    private async Task AssertRollbackWhenDcrStepThrows(ThrowingDcrService.Step step)
    {
        _harness.Settings.RequireInitialAccessToken = true;
        var (iatId, iatToken) = await SeedInitialAccessTokenAsync(isMultiUse: false);

        using (var op = _harness.NewOperation(
            dcrServiceFactory: (ctx, opt) => new ThrowingDcrService(ctx, opt, step)))
        {
            op.SetBearer(iatToken);
            var result = await op.Controller.Register(ValidRequest());
            result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(500);
        }

        // Whatever OpenIddict application was created inside the transaction must
        // be gone, along with the IAT consumption, any RAT, metadata, and audit.
        (await CountClientsAsync()).Should().Be(0);
        (await CountRegistrationTokensAsync()).Should().Be(0);
        (await CountRegistrationAuditsAsync()).Should().Be(0);
        (await IatUseCountAsync(iatId)).Should().Be(0);

        using var scope = _harness.NewVerificationScope();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var anyApp = false;
        await foreach (var _ in appManager.ListAsync()) { anyApp = true; }
        anyApp.Should().BeFalse("the OpenIddict application created mid-transaction must roll back");
    }

    // ==================== Retry after partial failure is idempotent ====================

    [Fact]
    public async Task Register_RetryAfterPartialFailure_IsIdempotent()
    {
        _harness.Settings.RequireInitialAccessToken = true;
        // Single-use token: only a full rollback of the failed attempt leaves it
        // usable for the retry, and only one client may ultimately exist.
        var (iatId, iatToken) = await SeedInitialAccessTokenAsync(isMultiUse: false);

        // First attempt fails after RAT persist.
        using (var op = _harness.NewOperation(
            dcrServiceFactory: (ctx, opt) => new ThrowingDcrService(ctx, opt, ThrowingDcrService.Step.Metadata)))
        {
            op.SetBearer(iatToken);
            var result = await op.Controller.Register(ValidRequest("first"));
            result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(500);
        }

        (await CountClientsAsync()).Should().Be(0);
        (await IatUseCountAsync(iatId)).Should().Be(0);

        // Retry with the same (still single-use) token succeeds exactly once.
        using (var op = _harness.NewOperation())
        {
            op.SetBearer(iatToken);
            var result = await op.Controller.Register(ValidRequest("second"));
            result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(201);
        }

        (await CountClientsAsync()).Should().Be(1, "retry must not duplicate registrations");
        (await CountRegistrationTokensAsync()).Should().Be(1);
        (await CountRegistrationAuditsAsync()).Should().Be(1);
        (await IatUseCountAsync(iatId)).Should().Be(1);
    }

    [Fact]
    public async Task Register_Success_ConsumesInitialAccessTokenExactlyOnce()
    {
        _harness.Settings.RequireInitialAccessToken = true;
        var (iatId, iatToken) = await SeedInitialAccessTokenAsync(isMultiUse: true, maxUses: 3);

        using (var op = _harness.NewOperation())
        {
            op.SetBearer(iatToken);
            var result = await op.Controller.Register(ValidRequest());
            result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(201);
        }

        (await IatUseCountAsync(iatId)).Should().Be(1);
    }

    // ==================== Orphan reconciliation ====================

    [Fact]
    public async Task Reconcile_RemovesOrphanedDcrApplication_ButKeepsValidAndNonDcrClients()
    {
        // 1. A proper, fully-registered DCR client (has metadata).
        string validClientId;
        using (var op = _harness.NewOperation())
        {
            var result = await op.Controller.Register(ValidRequest("valid"));
            validClientId = ((ClientRegistrationResponse)((ObjectResult)result).Value!).ClientId;
        }

        // 2. An orphaned DCR application: dcr_ prefix, no metadata.
        const string orphanClientId = "dcr_orphan_no_metadata";
        // 3. A genuine non-DCR application: no metadata, but no dcr_ prefix.
        const string seededClientId = "first-party-seeded";
        using (var scope = _harness.NewVerificationScope())
        {
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await appManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = orphanClientId,
                ClientType = OpenIddictConstants.ClientTypes.Public,
                DisplayName = "Orphan"
            });
            await appManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = seededClientId,
                ClientType = OpenIddictConstants.ClientTypes.Public,
                DisplayName = "Seeded first-party"
            });
        }

        // 4. An orphaned registration access token (no metadata, no application).
        using (var scope = _harness.NewVerificationScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            context.RegistrationAccessTokens.Add(new RegistrationAccessToken
            {
                ClientId = "dcr_orphan_token_only",
                TokenHash = Guid.NewGuid().ToString("N"),
                CreatedAt = DateTime.UtcNow
            });
            await context.SaveChangesAsync();
        }

        int removed;
        using (var scope = _harness.NewVerificationScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var reconciler = new DcrReconciliationService(
                context, appManager, NullLogger<DcrReconciliationService>.Instance);
            removed = await reconciler.ReconcileAsync();
        }

        removed.Should().Be(1, "only the orphaned DCR application should be removed");
        (await ApplicationExistsAsync(orphanClientId)).Should().BeFalse();
        (await ApplicationExistsAsync(validClientId)).Should().BeTrue("a properly registered DCR client is not an orphan");
        (await ApplicationExistsAsync(seededClientId)).Should().BeTrue("a non-DCR client is not an orphan");

        // The valid client's RAT survives; the orphaned RAT is swept.
        var survivingTokenClientIds = await ReadAsync(c =>
            c.RegistrationAccessTokens.Select(t => t.ClientId).ToListAsync());
        survivingTokenClientIds.Should().Contain(validClientId);
        survivingTokenClientIds.Should().NotContain("dcr_orphan_token_only");
    }

    /// <summary>
    /// DcrService that persists real rows up to a chosen step, then throws — so a
    /// test can prove the surrounding transaction rolls the persisted rows back.
    /// </summary>
    private sealed class ThrowingDcrService : DcrService
    {
        public enum Step { Rat, Metadata }

        private readonly Step _throwAt;

        public ThrowingDcrService(ApplicationDbContext context, IOptions<DcrSettings> settings, Step throwAt)
            : base(context, settings, NullLogger<DcrService>.Instance)
        {
            _throwAt = throwAt;
        }

        public override Task<(RegistrationAccessToken Entity, string PlainTextToken)> CreateRegistrationAccessTokenAsync(string clientId)
        {
            if (_throwAt == Step.Rat)
            {
                // Fail immediately after the application was persisted, before any RAT.
                throw new InvalidOperationException("injected: registration access token step");
            }

            return base.CreateRegistrationAccessTokenAsync(clientId);
        }

        public override async Task<DynamicClientRegistration> CreateDynamicClientRegistrationAsync(
            string clientId,
            int registrationAccessTokenId,
            int? initialAccessTokenId,
            bool requiresApproval,
            string? ipAddress,
            string? userAgent,
            long clientSecretExpiresAt = 0)
        {
            if (_throwAt == Step.Metadata)
            {
                // The RAT has already been persisted in this transaction; fail
                // before the metadata row so the RAT must roll back too.
                throw new InvalidOperationException("injected: metadata step");
            }

            return await base.CreateDynamicClientRegistrationAsync(
                clientId, registrationAccessTokenId, initialAccessTokenId,
                requiresApproval, ipAddress, userAgent, clientSecretExpiresAt);
        }
    }
}
