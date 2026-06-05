using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// SM.2.2 (rivoli-ai/conductor#2004) — unit tests for
/// <see cref="OAuthAuthorizationService"/>.
/// <para>
/// Covers every branch in the callback classifier and all legal/illegal
/// state-machine transitions, per the story's Tests section.
/// </para>
/// </summary>
public class OAuthAuthorizationServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly OAuthAuthorizationService _service;

    public OAuthAuthorizationServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);
        _service = new OAuthAuthorizationService(_context, new Mock<ILogger<OAuthAuthorizationService>>().Object);
    }

    public void Dispose() => _context.Dispose();

    // ── creation ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_PersistsAuthorizationAsPending()
    {
        var auth = await _service.CreateAsync("github", "raw-state-token", "user-1");

        auth.Should().NotBeNull();
        auth.State.Should().Be(OAuthAuthorizationState.Pending);
        auth.Provider.Should().Be("github");
        auth.SubjectId.Should().Be("user-1");
        auth.StateTokenHash.Should().NotBeNullOrEmpty();
        auth.StateTokenHash.Should().NotBe("raw-state-token"); // must be hashed
        auth.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        auth.AuthorizationId.Should().NotBe(Guid.Empty);
    }

    [Fact]
    public async Task Create_HashesStateToken_NotStoredInPlaintext()
    {
        const string raw = "supersecretstate123";
        var auth = await _service.CreateAsync("gitlab", raw);

        // SHA-256 hex is 64 chars
        auth.StateTokenHash.Should().HaveLength(64);
        auth.StateTokenHash.Should().NotBe(raw);
    }

    // ── callback classifier — every branch ───────────────────────────────────

    [Fact]
    public async Task ClassifyCallback_AccessDenied_ReturnsUserDenied_PersistsFailed()
    {
        var auth = await _service.CreateAsync("github", "token");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: "access_denied",
            returnedStateToken: null,
            codePresent: false,
            tokenExchangeSuccess: null);

        result.Result.Should().Be(CallbackResult.UserDenied);
        result.AuthorizationId.Should().Be(auth.AuthorizationId);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed);
        persisted.FailureReason.Should().Be(OAuthFailureReason.UserDenied);
        persisted.CompletedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task ClassifyCallback_StateMismatch_ReturnsStateMismatch_NotGenericError()
    {
        var auth = await _service.CreateAsync("github", "correct-token");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: null,
            returnedStateToken: "wrong-token",
            codePresent: true,
            tokenExchangeSuccess: null);

        result.Result.Should().Be(CallbackResult.StateMismatch);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed);
        persisted.FailureReason.Should().Be(OAuthFailureReason.StateMismatch);
    }

    [Fact]
    public async Task ClassifyCallback_NoStateReturned_ReturnsStateMismatch()
    {
        // Provider sent no state back — treat as CSRF mismatch, not a generic error.
        var auth = await _service.CreateAsync("github", "expected-state");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: null,
            returnedStateToken: null,  // Provider sent no state
            codePresent: true,
            tokenExchangeSuccess: null);

        result.Result.Should().Be(CallbackResult.StateMismatch);
    }

    [Fact]
    public async Task ClassifyCallback_TokenExchangeFailed_ReturnsTokenExchangeFailed()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: null,
            returnedStateToken: "state",  // matches
            codePresent: true,
            tokenExchangeSuccess: false,
            tokenExchangeDetail: "Provider returned 403 Forbidden");

        result.Result.Should().Be(CallbackResult.TokenExchangeFailed);
        result.Detail.Should().Contain("403");

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed);
        persisted.FailureReason.Should().Be(OAuthFailureReason.TokenExchangeFailed);
    }

    [Fact]
    public async Task ClassifyCallback_HappyPath_ReturnsSuccess_PersistsCompleted()
    {
        var auth = await _service.CreateAsync("github", "valid-state");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: null,
            returnedStateToken: "valid-state",
            codePresent: true,
            tokenExchangeSuccess: true,
            connectionId: "conn-42");

        result.Result.Should().Be(CallbackResult.Success);
        result.AuthorizationId.Should().Be(auth.AuthorizationId);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Completed);
        persisted.FailureReason.Should().BeNull();
        persisted.ConnectionId.Should().Be("conn-42");
        persisted.CompletedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task ClassifyCallback_NeitherErrorNorCode_ReturnsInvalidCallback()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: null,
            returnedStateToken: "state",
            codePresent: false,     // no code
            tokenExchangeSuccess: null);

        result.Result.Should().Be(CallbackResult.InvalidCallback);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed);
        persisted.FailureReason.Should().Be(OAuthFailureReason.InvalidCallback);
    }

    [Fact]
    public async Task ClassifyCallback_OtherProviderError_ReturnsInvalidCallback()
    {
        // A non-access_denied error (e.g. "temporarily_unavailable") should map
        // to InvalidCallback rather than UserDenied.
        var auth = await _service.CreateAsync("github", "state");

        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId,
            providerError: "temporarily_unavailable",
            returnedStateToken: null,
            codePresent: false,
            tokenExchangeSuccess: null);

        result.Result.Should().Be(CallbackResult.InvalidCallback);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.FailureReason.Should().Be(OAuthFailureReason.InvalidCallback);
    }

    [Fact]
    public async Task ClassifyCallback_UnknownAuthorizationId_ReturnsInvalidCallback()
    {
        var result = await _service.ClassifyCallbackAsync(
            Guid.NewGuid(), // does not exist
            providerError: null,
            returnedStateToken: "state",
            codePresent: true,
            tokenExchangeSuccess: true);

        result.Result.Should().Be(CallbackResult.InvalidCallback);
        result.AuthorizationId.Should().BeNull();
    }

    // ── state-machine transitions ─────────────────────────────────────────────

    [Fact]
    public async Task StateMachine_PendingToCompleted_Allowed()
    {
        var auth = await _service.CreateAsync("github", "state");
        auth.State.Should().Be(OAuthAuthorizationState.Pending);

        await _service.ClassifyCallbackAsync(auth.AuthorizationId, null, "state", true, true);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Completed);
    }

    [Fact]
    public async Task StateMachine_PendingToFailed_Allowed()
    {
        var auth = await _service.CreateAsync("github", "state");

        await _service.ClassifyCallbackAsync(auth.AuthorizationId, "access_denied", null, false, null);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed);
    }

    [Fact]
    public async Task StateMachine_IllegalTransition_CompletedToFailed_Rejected_IdempotentReturn()
    {
        // A replay of a callback for an already-Completed authorization must
        // return the existing outcome (409-idempotency) rather than mutating state.
        var auth = await _service.CreateAsync("github", "state");

        // First callback: succeeds → Completed
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, null, "state", true, true);

        // Second callback replay: access_denied — must NOT flip Completed→Failed.
        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId, "access_denied", null, false, null);

        // Returns existing terminal outcome (Completed/Success), not the replayed error.
        result.Result.Should().Be(CallbackResult.Success);

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Completed); // unchanged
    }

    [Fact]
    public async Task StateMachine_IllegalTransition_FailedToCompleted_Rejected()
    {
        var auth = await _service.CreateAsync("github", "state");

        // First: fail
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, "access_denied", null, false, null);

        // Second replay claiming success — must not flip Failed→Completed.
        var result = await _service.ClassifyCallbackAsync(
            auth.AuthorizationId, null, "state", true, true);

        result.Result.Should().Be(CallbackResult.UserDenied); // existing terminal outcome

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed); // unchanged
    }

    // ── expiry ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StateMachine_PendingToExpired_LazyOnStatusQuery()
    {
        var auth = await _service.CreateAsync("github", "state", ttl: TimeSpan.FromMilliseconds(1));

        // Wait for the TTL to elapse so the record becomes stale.
        await Task.Delay(10);

        var status = await _service.GetStatusAsync(auth.AuthorizationId);

        status.Should().NotBeNull();
        status!.State.Should().Be(OAuthAuthorizationState.Expired);
    }

    [Fact]
    public async Task StatusQuery_OrphanedAuth_ReportsExpiredNotSilentlyPending()
    {
        // An orphaned authorization (crash mid-exchange, TTL elapsed) must
        // never return an ambiguous "still pending" that strands the client.
        var auth = await _service.CreateAsync("github", "state", ttl: TimeSpan.FromMilliseconds(1));
        await Task.Delay(10);

        var status = await _service.GetStatusAsync(auth.AuthorizationId);

        status!.State.Should().Be(OAuthAuthorizationState.Expired);
        status.FailureReason.Should().NotBeNull();
    }

    [Fact]
    public async Task ExpireStaleAuthorizations_MarksPendingExpiredRecords()
    {
        // Seed 3 Pending records, all with TTL in the past.
        for (var i = 0; i < 3; i++)
        {
            var a = new OAuthAuthorization
            {
                Provider = "github",
                State = OAuthAuthorizationState.Pending,
                CreatedAt = DateTime.UtcNow.AddMinutes(-20),
                ExpiresAt = DateTime.UtcNow.AddMinutes(-10)
            };
            _context.OAuthAuthorizations.Add(a);
        }
        // One Completed — should not be touched.
        _context.OAuthAuthorizations.Add(new OAuthAuthorization
        {
            Provider = "github",
            State = OAuthAuthorizationState.Completed,
            CreatedAt = DateTime.UtcNow.AddMinutes(-20),
            ExpiresAt = DateTime.UtcNow.AddMinutes(-10),
            CompletedAt = DateTime.UtcNow.AddMinutes(-15)
        });
        await _context.SaveChangesAsync();

        var count = await _service.ExpireStaleAuthorizationsAsync();

        count.Should().Be(3);
        var pending = await _context.OAuthAuthorizations
            .Where(a => a.State == OAuthAuthorizationState.Pending)
            .CountAsync();
        pending.Should().Be(0);
    }

    // ── status / crash reconciliation ─────────────────────────────────────────

    [Fact]
    public async Task GetStatus_CompletedAuth_ReturnsCorrectFields()
    {
        var auth = await _service.CreateAsync("github", "state");
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, null, "state", true, true, connectionId: "conn-99");

        var status = await _service.GetStatusAsync(auth.AuthorizationId);

        status.Should().NotBeNull();
        status!.State.Should().Be(OAuthAuthorizationState.Completed);
        status.FailureReason.Should().BeNull();
        status.ConnectionId.Should().Be("conn-99");
        status.CompletedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task GetStatus_FailedAuth_ReturnsFailureReason()
    {
        var auth = await _service.CreateAsync("github", "state");
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, "access_denied", null, false, null);

        var status = await _service.GetStatusAsync(auth.AuthorizationId);

        status!.State.Should().Be(OAuthAuthorizationState.Failed);
        status.FailureReason.Should().Be(OAuthFailureReason.UserDenied);
    }

    [Fact]
    public async Task GetStatus_UnknownId_ReturnsNull()
    {
        var status = await _service.GetStatusAsync(Guid.NewGuid());
        status.Should().BeNull();
    }

    // ── async exchange result ─────────────────────────────────────────────────

    [Fact]
    public async Task MarkTokenExchangeResult_Success_TransitionsToCompleted()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _service.MarkTokenExchangeResultAsync(auth.AuthorizationId, true, connectionId: "conn-5");

        result.Result.Should().Be(CallbackResult.Success);
        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Completed);
        persisted.ConnectionId.Should().Be("conn-5");
    }

    [Fact]
    public async Task MarkTokenExchangeResult_Failure_TransitionsToFailed()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _service.MarkTokenExchangeResultAsync(
            auth.AuthorizationId, false, detail: "500 from provider");

        result.Result.Should().Be(CallbackResult.TokenExchangeFailed);
        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Failed);
        persisted.FailureReason.Should().Be(OAuthFailureReason.TokenExchangeFailed);
        persisted.FailureDetail.Should().Contain("500");
    }

    // ── user_denied vs exchange_failed discriminability ───────────────────────

    [Fact]
    public async Task UserDenied_IsDistinguishableFrom_ExchangeFailed()
    {
        // AC: user_denied (OAuthError.permissionDenied) must be a distinct result
        // from token_exchange_failed (OAuthError.exchangeFailed).
        var authDenied = await _service.CreateAsync("github", "s1");
        var authFailed = await _service.CreateAsync("github", "s2");

        var denied = await _service.ClassifyCallbackAsync(
            authDenied.AuthorizationId, "access_denied", null, false, null);
        var failed = await _service.ClassifyCallbackAsync(
            authFailed.AuthorizationId, null, "s2", true, false, "HTTP 500");

        denied.Result.Should().Be(CallbackResult.UserDenied);
        failed.Result.Should().Be(CallbackResult.TokenExchangeFailed);
        denied.Result.Should().NotBe(failed.Result);
    }

    [Fact]
    public async Task UserDenied_IsDistinguishableFrom_StateMismatch()
    {
        var authDenied = await _service.CreateAsync("github", "s1");
        var authMismatch = await _service.CreateAsync("github", "s2");

        var denied = await _service.ClassifyCallbackAsync(
            authDenied.AuthorizationId, "access_denied", null, false, null);
        var mismatch = await _service.ClassifyCallbackAsync(
            authMismatch.AuthorizationId, null, "wrong-state", true, null);

        denied.Result.Should().Be(CallbackResult.UserDenied);
        mismatch.Result.Should().Be(CallbackResult.StateMismatch);
        denied.Result.Should().NotBe(mismatch.Result);
    }
}
