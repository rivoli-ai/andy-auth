using Andy.Auth.Server.Controllers.Api;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using Xunit;

namespace Andy.Auth.Server.Tests.Api;

/// <summary>
/// SM.2.2 (rivoli-ai/conductor#2004) — integration tests for the
/// <see cref="OAuthAuthorizationsController"/> endpoints.
/// <para>
/// Covers the acceptance-criteria contract:
/// <list type="bullet">
/// <item>Structured callback outcome discriminator (success/user_denied/state_mismatch/token_exchange_failed/invalid_callback).</item>
/// <item>GET /auth/oauth/authorizations/{id} returns authoritative state for crash reconciliation.</item>
/// <item>user_denied is distinguishable from state_mismatch and token_exchange_failed.</item>
/// <item>Orphaned Pending → Expired on status query (never ambiguous silence).</item>
/// <item>Replay of already-terminal callback returns 409-idempotency outcome, not an error.</item>
/// </list>
/// </para>
/// </summary>
public class OAuthAuthorizationsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly OAuthAuthorizationService _service;
    private readonly OAuthAuthorizationsController _controller;

    public OAuthAuthorizationsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);
        _service = new OAuthAuthorizationService(
            _context, new Mock<ILogger<OAuthAuthorizationService>>().Object);
        _controller = new OAuthAuthorizationsController(
            _service, new Mock<ILogger<OAuthAuthorizationsController>>().Object);

        // Set up a signed-in user principal.
        var claims = new[] { new Claim("sub", "user-test-1") };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    public void Dispose() => _context.Dispose();

    // ── create ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_ValidRequest_Returns201WithAuthorizationId()
    {
        var result = await _controller.Create(new CreateAuthorizationRequest
        {
            Provider = "github",
            StateToken = "test-state-token"
        });

        var created = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        created.StatusCode.Should().Be(StatusCodes.Status201Created);
        var dto = created.Value.Should().BeOfType<AuthorizationCreatedDto>().Subject;
        dto.AuthorizationId.Should().NotBe(Guid.Empty);
        dto.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task Create_MissingProvider_Returns400()
    {
        var result = await _controller.Create(new CreateAuthorizationRequest
        {
            Provider = "",
            StateToken = "token"
        });

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Create_MissingStateToken_Returns400()
    {
        var result = await _controller.Create(new CreateAuthorizationRequest
        {
            Provider = "github",
            StateToken = ""
        });

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    // ── callback — outcome discriminator ─────────────────────────────────────

    [Fact]
    public async Task Callback_AccessDenied_Returns200WithUserDenied()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ProviderError = "access_denied",
                ReturnedStateToken = null,
                CodePresent = false
            });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        ok.StatusCode.Should().Be(StatusCodes.Status200OK);
        var dto = ok.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("user_denied");
        dto.AuthorizationId.Should().Be(auth.AuthorizationId);
    }

    [Fact]
    public async Task Callback_StateMismatch_Returns200WithStateMismatch_NotGenericError()
    {
        // AC: tampered state token → state_mismatch (not a generic 400).
        var auth = await _service.CreateAsync("github", "expected");

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ProviderError = null,
                ReturnedStateToken = "tampered",   // wrong
                CodePresent = true
            });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        ok.StatusCode.Should().Be(StatusCodes.Status200OK);
        var dto = ok.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("state_mismatch");
        dto.Result.Should().NotBe("invalid_callback"); // must be specifically state_mismatch
    }

    [Fact]
    public async Task Callback_TokenExchangeFailed_Returns200WithTokenExchangeFailed()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ProviderError = null,
                ReturnedStateToken = "state",
                CodePresent = true,
                TokenExchangeSuccess = false,
                TokenExchangeDetail = "Provider returned 401"
            });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("token_exchange_failed");
    }

    [Fact]
    public async Task Callback_HappyPath_Returns200WithSuccess()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ProviderError = null,
                ReturnedStateToken = "state",
                CodePresent = true,
                TokenExchangeSuccess = true,
                ConnectionId = "conn-1"
            });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("success");
    }

    [Fact]
    public async Task Callback_UnknownId_Returns404()
    {
        var result = await _controller.RecordCallback(Guid.NewGuid(),
            new RecordCallbackRequest { CodePresent = true, ReturnedStateToken = "s" });

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task Callback_ReplayForAlreadyCompletedAuth_Returns200WithExistingOutcome_NotError()
    {
        // AC: replaying a callback for an already-Completed authorization returns
        // the existing outcome (409-like idempotency reconcile-forward), not a throw.
        var auth = await _service.CreateAsync("github", "state");
        // First callback: success
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, null, "state", true, true);

        // Replay with access_denied — must not flip state.
        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ProviderError = "access_denied",
                CodePresent = false
            });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        // Returns the ORIGINAL success outcome, not the replayed denial.
        dto.Result.Should().Be("success");

        // State must not have changed.
        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Completed);
    }

    // ── GET status — crash reconciliation ─────────────────────────────────────

    [Fact]
    public async Task GetStatus_CompletedAuth_Returns200WithCompletedState()
    {
        var auth = await _service.CreateAsync("github", "state");
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, null, "state", true, true, connectionId: "conn-7");

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<AuthorizationStatusDto>().Subject;
        dto.State.Should().Be("completed");
        dto.FailureReason.Should().BeNull();
        dto.ConnectionId.Should().Be("conn-7");
        dto.CompletedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task GetStatus_FailedAuth_Returns200WithFailureReason()
    {
        var auth = await _service.CreateAsync("github", "state");
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, "access_denied", null, false, null);

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<AuthorizationStatusDto>().Subject;
        dto.State.Should().Be("failed");
        dto.FailureReason.Should().Be("user_denied");
    }

    [Fact]
    public async Task GetStatus_PendingAuth_Returns200WithPendingState()
    {
        var auth = await _service.CreateAsync("github", "state");

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<AuthorizationStatusDto>().Subject;
        dto.State.Should().Be("pending");
        dto.FailureReason.Should().BeNull();
    }

    [Fact]
    public async Task GetStatus_OrphanedAuth_ReportsExpired_NeverAmbiguousSilence()
    {
        // AC: orphaned authorization (client crashed mid-exchange, never got callback)
        // is reconcilable: status endpoint reports expired, NOT ambiguous "still pending".
        var auth = await _service.CreateAsync("github", "state", ttl: TimeSpan.FromMilliseconds(1));
        await Task.Delay(10); // wait for TTL to elapse

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<AuthorizationStatusDto>().Subject;
        dto.State.Should().Be("expired");
        // Client can map this to OAuthError.invalidCallback → surface a "retry" affordance.
    }

    [Fact]
    public async Task GetStatus_UnknownId_Returns404()
    {
        var result = await _controller.GetStatus(Guid.NewGuid());
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ── discriminability: AC verification ────────────────────────────────────

    [Fact]
    public async Task UserDenied_MapsToUserDeniedResult_NotExchangeFailed_AndNotStateMismatch()
    {
        // AC: user-denied is distinguishable from network/exchange failure
        // (maps to OAuthError.permissionDenied vs .exchangeFailed) and from CSRF.
        var a1 = await _service.CreateAsync("github", "s1");
        var a2 = await _service.CreateAsync("github", "s2");
        var a3 = await _service.CreateAsync("github", "s3");

        var denied = await _controller.RecordCallback(a1.AuthorizationId,
            new RecordCallbackRequest { ProviderError = "access_denied" });
        var exchangeFailed = await _controller.RecordCallback(a2.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "s2", CodePresent = true, TokenExchangeSuccess = false });
        var stateMismatch = await _controller.RecordCallback(a3.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "wrong", CodePresent = true });

        var d = ((ObjectResult)denied).Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        var e = ((ObjectResult)exchangeFailed).Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        var s = ((ObjectResult)stateMismatch).Value.Should().BeOfType<CallbackOutcomeDto>().Subject;

        d.Result.Should().Be("user_denied");
        e.Result.Should().Be("token_exchange_failed");
        s.Result.Should().Be("state_mismatch");

        // All three must be distinct.
        new[] { d.Result, e.Result, s.Result }.Distinct().Should().HaveCount(3);
    }
}
