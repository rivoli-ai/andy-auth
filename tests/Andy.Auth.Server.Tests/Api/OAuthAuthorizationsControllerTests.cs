using Andy.Auth.Server.Controllers.Api;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using Xunit;

namespace Andy.Auth.Server.Tests.Api;

/// <summary>
/// SM.2.2 (rivoli-ai/conductor#2004) + issue #123 — integration tests for the
/// <see cref="OAuthAuthorizationsController"/> endpoints.
/// <para>
/// Covers the SM.2.2 callback-outcome contract plus the #123 authorization
/// hardening:
/// <list type="bullet">
/// <item>Callback / exchange-result mutations require a signed capability bound
///   to (authorization id + provider) OR an authorized service identity — the
///   UUID alone is never sufficient.</item>
/// <item>Tampered / expired / mis-bound capabilities are rejected (403).</item>
/// <item>Status reads require the initiating subject or a service identity (403 otherwise).</item>
/// <item>Replaying a terminal record returns 409 with the existing outcome.</item>
/// </list>
/// </para>
/// </summary>
public class OAuthAuthorizationsControllerTests : IDisposable
{
    private const string OwnerSubject = "user-test-1";

    private readonly ApplicationDbContext _context;
    private readonly OAuthAuthorizationService _service;
    private readonly OAuthCallbackCapabilityService _capabilities;
    private readonly OAuthAuthorizationsController _controller;
    private readonly DefaultHttpContext _httpContext = new();

    public OAuthAuthorizationsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);
        _service = new OAuthAuthorizationService(
            _context, new Mock<ILogger<OAuthAuthorizationService>>().Object);
        _capabilities = new OAuthCallbackCapabilityService(new EphemeralDataProtectionProvider());
        _controller = new OAuthAuthorizationsController(
            _service, _capabilities, new Mock<ILogger<OAuthAuthorizationsController>>().Object);

        _controller.ControllerContext = new ControllerContext { HttpContext = _httpContext };

        // Default caller: the initiating end-user (authenticated, non-admin).
        SetPrincipal(OwnerSubject);
    }

    public void Dispose() => _context.Dispose();

    // ── test helpers ───────────────────────────────────────────────────────────

    private void SetPrincipal(string? subject, bool isServiceIdentity = false)
    {
        var claims = new List<Claim>();
        if (subject != null) claims.Add(new Claim("sub", subject));
        if (isServiceIdentity) claims.Add(new Claim(ClaimTypes.Role, "Admin"));
        _httpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
    }

    private void SetCapabilityHeader(Guid authorizationId, string provider)
    {
        _httpContext.Request.Headers[OAuthAuthorizationsController.CapabilityHeader] =
            _capabilities.Issue(authorizationId, provider, DateTime.UtcNow.AddMinutes(10));
    }

    private void ClearCapabilityHeader() =>
        _httpContext.Request.Headers.Remove(OAuthAuthorizationsController.CapabilityHeader);

    private Task<OAuthAuthorization> CreateOwnedAsync(
        string provider = "github", string state = "state", TimeSpan? ttl = null) =>
        _service.CreateAsync(provider, state, OwnerSubject, ttl);

    // ── create ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_ValidRequest_Returns201WithAuthorizationIdAndCapability()
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
        dto.CallbackToken.Should().NotBeNullOrEmpty();

        // The minted capability authorizes the callback for this id + provider.
        _capabilities.Validate(dto.CallbackToken, dto.AuthorizationId, "github").Should().BeTrue();
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

    // ── callback — outcome discriminator (with capability) ────────────────────

    [Fact]
    public async Task Callback_AccessDenied_Returns200WithUserDenied()
    {
        var auth = await CreateOwnedAsync();
        SetCapabilityHeader(auth.AuthorizationId, "github");

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
        var auth = await CreateOwnedAsync(state: "expected");
        SetCapabilityHeader(auth.AuthorizationId, "github");

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
        dto.Result.Should().NotBe("invalid_callback");
    }

    [Fact]
    public async Task Callback_TokenExchangeFailed_Returns200WithTokenExchangeFailed()
    {
        var auth = await CreateOwnedAsync();
        SetCapabilityHeader(auth.AuthorizationId, "github");

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
        var auth = await CreateOwnedAsync();
        SetCapabilityHeader(auth.AuthorizationId, "github");

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
        // Unknown id: no record to bind a capability to → 404 before authorization.
        var result = await _controller.RecordCallback(Guid.NewGuid(),
            new RecordCallbackRequest { CodePresent = true, ReturnedStateToken = "s" });

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ── callback — authorization (issue #123) ─────────────────────────────────

    [Fact]
    public async Task Callback_NoCapability_NonServiceCaller_Returns401_UuidNotSufficient()
    {
        // AC: knowledge of the authorization UUID is NOT sufficient authorization.
        var auth = await CreateOwnedAsync();
        ClearCapabilityHeader();
        SetPrincipal(OwnerSubject); // authenticated end-user, not a service identity

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "state", CodePresent = true, TokenExchangeSuccess = true });

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);

        // State must not have transitioned.
        var persisted = await _context.OAuthAuthorizations.AsNoTracking()
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Pending);
    }

    [Fact]
    public async Task Callback_TamperedCapability_Returns403()
    {
        // AC (tampering): a mutated capability token must be rejected.
        var auth = await CreateOwnedAsync();
        var valid = _capabilities.Issue(auth.AuthorizationId, "github", DateTime.UtcNow.AddMinutes(10));
        _httpContext.Request.Headers[OAuthAuthorizationsController.CapabilityHeader] =
            valid + "tampered";

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "state", CodePresent = true, TokenExchangeSuccess = true });

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status403Forbidden);

        var persisted = await _context.OAuthAuthorizations.AsNoTracking()
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Pending);
    }

    [Fact]
    public async Task Callback_CapabilityBoundToDifferentProvider_Returns403()
    {
        // AC: callback state is bound to authorization id AND provider.
        var auth = await CreateOwnedAsync(provider: "github");
        _httpContext.Request.Headers[OAuthAuthorizationsController.CapabilityHeader] =
            _capabilities.Issue(auth.AuthorizationId, "gitlab", DateTime.UtcNow.AddMinutes(10)); // wrong provider

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "state", CodePresent = true, TokenExchangeSuccess = true });

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
    }

    [Fact]
    public async Task Callback_CapabilityBoundToDifferentAuthorization_Returns403()
    {
        var auth = await CreateOwnedAsync();
        var other = await CreateOwnedAsync();
        // Present a capability minted for a DIFFERENT authorization id.
        _httpContext.Request.Headers[OAuthAuthorizationsController.CapabilityHeader] =
            _capabilities.Issue(other.AuthorizationId, "github", DateTime.UtcNow.AddMinutes(10));

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "state", CodePresent = true, TokenExchangeSuccess = true });

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
    }

    [Fact]
    public async Task Callback_ServiceIdentity_WithoutCapability_Succeeds()
    {
        // The broker/service identity may drive the callback without a capability.
        var auth = await CreateOwnedAsync();
        ClearCapabilityHeader();
        SetPrincipal("svc-broker", isServiceIdentity: true);

        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ReturnedStateToken = "state",
                CodePresent = true,
                TokenExchangeSuccess = true,
                ConnectionId = "conn-svc"
            });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        ok.StatusCode.Should().Be(StatusCodes.Status200OK);
        var dto = ok.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("success");
    }

    // ── replay → 409 (issue #123) ─────────────────────────────────────────────

    [Fact]
    public async Task Callback_ReplayForAlreadyCompletedAuth_Returns409WithExistingOutcome()
    {
        // AC: replays return the documented 409 with the existing outcome.
        var auth = await CreateOwnedAsync();
        // First callback: success (via service).
        await _service.ClassifyCallbackAsync(auth.AuthorizationId, null, "state", true, true);

        SetCapabilityHeader(auth.AuthorizationId, "github");
        var result = await _controller.RecordCallback(auth.AuthorizationId,
            new RecordCallbackRequest
            {
                ProviderError = "access_denied", // replay tries to flip state
                CodePresent = false
            });

        var conflict = result.Should().BeOfType<ObjectResult>().Subject;
        conflict.StatusCode.Should().Be(StatusCodes.Status409Conflict);
        var dto = conflict.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("success"); // original outcome preserved

        var persisted = await _context.OAuthAuthorizations
            .FirstAsync(a => a.AuthorizationId == auth.AuthorizationId);
        persisted.State.Should().Be(OAuthAuthorizationState.Completed);
    }

    [Fact]
    public async Task ExchangeResult_ReplayForTerminalAuth_Returns409()
    {
        var auth = await CreateOwnedAsync();
        await _service.MarkTokenExchangeResultAsync(auth.AuthorizationId, true, connectionId: "conn-1");

        SetCapabilityHeader(auth.AuthorizationId, "github");
        var result = await _controller.MarkExchangeResult(auth.AuthorizationId,
            new MarkExchangeResultRequest { Success = false, Detail = "replay" });

        var conflict = result.Should().BeOfType<ObjectResult>().Subject;
        conflict.StatusCode.Should().Be(StatusCodes.Status409Conflict);
        var dto = conflict.Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        dto.Result.Should().Be("success");
    }

    [Fact]
    public async Task ExchangeResult_FirstCall_Returns200()
    {
        var auth = await CreateOwnedAsync();
        SetCapabilityHeader(auth.AuthorizationId, "github");

        var result = await _controller.MarkExchangeResult(auth.AuthorizationId,
            new MarkExchangeResultRequest { Success = true, ConnectionId = "conn-1" });

        var ok = result.Should().BeOfType<ObjectResult>().Subject;
        ok.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task ExchangeResult_NoCapability_NonServiceCaller_Returns401()
    {
        var auth = await CreateOwnedAsync();
        ClearCapabilityHeader();

        var result = await _controller.MarkExchangeResult(auth.AuthorizationId,
            new MarkExchangeResultRequest { Success = true });

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    // ── GET status — crash reconciliation ─────────────────────────────────────

    [Fact]
    public async Task GetStatus_CompletedAuth_Returns200WithCompletedState()
    {
        var auth = await CreateOwnedAsync();
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
        var auth = await CreateOwnedAsync();
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
        var auth = await CreateOwnedAsync();

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<AuthorizationStatusDto>().Subject;
        dto.State.Should().Be("pending");
        dto.FailureReason.Should().BeNull();
    }

    [Fact]
    public async Task GetStatus_OrphanedAuth_ReportsExpired_NeverAmbiguousSilence()
    {
        var auth = await CreateOwnedAsync(ttl: TimeSpan.FromMilliseconds(1));
        await Task.Delay(10);

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<AuthorizationStatusDto>().Subject;
        dto.State.Should().Be("expired");
    }

    [Fact]
    public async Task GetStatus_UnknownId_Returns404()
    {
        var result = await _controller.GetStatus(Guid.NewGuid());
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ── GET status — ownership (issue #123) ───────────────────────────────────

    [Fact]
    public async Task GetStatus_NonOwner_Returns403_UuidNotSufficient()
    {
        // AC: knowledge of the UUID is not sufficient — a different subject is denied.
        var auth = await CreateOwnedAsync(); // owned by OwnerSubject
        SetPrincipal("someone-else");        // authenticated, but not the owner / not a service

        var result = await _controller.GetStatus(auth.AuthorizationId);

        result.Should().BeOfType<ForbidResult>();
    }

    [Fact]
    public async Task GetStatus_ServiceIdentity_CanReadAnyRecord()
    {
        var auth = await CreateOwnedAsync(); // owned by OwnerSubject
        SetPrincipal("svc-broker", isServiceIdentity: true);

        var result = await _controller.GetStatus(auth.AuthorizationId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<AuthorizationStatusDto>();
    }

    [Fact]
    public async Task GetStatus_AnonymousOwnedRecord_NonServiceCaller_Returns403()
    {
        // A record created with no initiating subject can only be read by a
        // service identity — not by an arbitrary authenticated user.
        var auth = await _service.CreateAsync("github", "state"); // SubjectId == null
        SetPrincipal(OwnerSubject);

        var result = await _controller.GetStatus(auth.AuthorizationId);

        result.Should().BeOfType<ForbidResult>();
    }

    [Fact]
    public async Task GetStatus_Owner_CanReadOwnRecord()
    {
        var auth = await CreateOwnedAsync();
        SetPrincipal(OwnerSubject);

        var result = await _controller.GetStatus(auth.AuthorizationId);

        result.Should().BeOfType<OkObjectResult>();
    }

    // ── discriminability: AC verification ────────────────────────────────────

    [Fact]
    public async Task UserDenied_MapsToUserDeniedResult_NotExchangeFailed_AndNotStateMismatch()
    {
        var a1 = await CreateOwnedAsync(state: "s1");
        var a2 = await CreateOwnedAsync(state: "s2");
        var a3 = await CreateOwnedAsync(state: "s3");

        SetCapabilityHeader(a1.AuthorizationId, "github");
        var denied = await _controller.RecordCallback(a1.AuthorizationId,
            new RecordCallbackRequest { ProviderError = "access_denied" });

        SetCapabilityHeader(a2.AuthorizationId, "github");
        var exchangeFailed = await _controller.RecordCallback(a2.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "s2", CodePresent = true, TokenExchangeSuccess = false });

        SetCapabilityHeader(a3.AuthorizationId, "github");
        var stateMismatch = await _controller.RecordCallback(a3.AuthorizationId,
            new RecordCallbackRequest { ReturnedStateToken = "wrong", CodePresent = true });

        var d = ((ObjectResult)denied).Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        var e = ((ObjectResult)exchangeFailed).Value.Should().BeOfType<CallbackOutcomeDto>().Subject;
        var s = ((ObjectResult)stateMismatch).Value.Should().BeOfType<CallbackOutcomeDto>().Subject;

        d.Result.Should().Be("user_denied");
        e.Result.Should().Be("token_exchange_failed");
        s.Result.Should().Be("state_mismatch");

        new[] { d.Result, e.Result, s.Result }.Distinct().Should().HaveCount(3);
    }
}
