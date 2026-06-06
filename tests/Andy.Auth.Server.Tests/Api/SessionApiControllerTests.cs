using Andy.Auth.Server.Controllers.Api;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using Xunit;

namespace Andy.Auth.Server.Tests.Api;

/// <summary>
/// SM.2.1 (rivoli-ai/conductor#2003) — proves the GET /auth/session endpoint
/// cleanly separates the three permanent/transient outcomes that the #1861
/// "all-red on launch" conflation used to merge:
///   200 (truth) · 410 (revoked, permanent) · 401 (invalid token, permanent)
///   · 503 (temporarily_unavailable, transient).
/// The headline guard is <c>Transient503_DoesNotCollapseTo401</c>.
/// </summary>
public class SessionApiControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly SessionService _sessionService;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<SignInManager<ApplicationUser>> _signInManagerMock;
    private readonly Mock<ILogger<SessionApiController>> _loggerMock;

    public SessionApiControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);

        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SessionManagement:MaxConcurrentSessions"] = "5",
            ["SessionManagement:SessionTimeout"] = "30.00:00:00",
            ["SessionManagement:InactivityTimeout"] = "7.00:00:00"
        }).Build();
        _sessionService = new SessionService(_context, new Mock<ILogger<SessionService>>().Object, config);

        _userManagerMock = MockUserManager();
        _signInManagerMock = MockSignInManager(_userManagerMock.Object);
        _loggerMock = new Mock<ILogger<SessionApiController>>();

        // Default: account exists and can sign in.
        _signInManagerMock
            .Setup(s => s.CanSignInAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(true);
    }

    public void Dispose() => _context.Dispose();

    private SessionApiController BuildController(string? subject, string? sessionId = null)
    {
        var controller = new SessionApiController(
            _sessionService, _userManagerMock.Object, _signInManagerMock.Object, _loggerMock.Object);

        var claims = new List<Claim>();
        if (subject != null) claims.Add(new Claim("sub", subject));
        if (sessionId != null) claims.Add(new Claim("session_id", sessionId));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
        return controller;
    }

    private async Task SeedSessionAsync(string userId, string sessionId,
        bool revoked = false, DateTime? expiresAt = null, string? reason = null)
    {
        _context.UserSessions.Add(new UserSession
        {
            UserId = userId,
            SessionId = sessionId,
            CreatedAt = DateTime.UtcNow.AddHours(-1),
            LastActivity = DateTime.UtcNow,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddDays(30),
            IsRevoked = revoked,
            RevokedAt = revoked ? DateTime.UtcNow : null,
            RevocationReason = revoked ? (reason ?? "session_revoked") : null
        });
        await _context.SaveChangesAsync();
    }

    private void SetupExistingUser(string id)
    {
        _userManagerMock
            .Setup(m => m.FindByIdAsync(id))
            .ReturnsAsync(new ApplicationUser { Id = id, Email = $"{id}@test.com", UserName = $"{id}@test.com" });
    }

    [Fact]
    public async Task GetSession_LiveSession_Returns200Authenticated()
    {
        SetupExistingUser("user-1");
        await SeedSessionAsync("user-1", "sess-1", expiresAt: DateTime.UtcNow.AddDays(5));
        var controller = BuildController("user-1");

        var result = await controller.GetSession();

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<SessionTruthDto>().Subject;
        dto.Authenticated.Should().BeTrue();
        dto.Revoked.Should().BeFalse();
        dto.Subject.Should().Be("user-1");
        dto.SessionId.Should().Be("sess-1");
        dto.ExpiresAt.Should().NotBeNull();
    }

    [Fact]
    public async Task GetSession_RevokedSession_Returns410SessionRevoked()
    {
        SetupExistingUser("user-2");
        await SeedSessionAsync("user-2", "sess-2", revoked: true, reason: "Admin force-logout");
        var controller = BuildController("user-2", "sess-2");

        var result = await controller.GetSession();

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status410Gone);
        var err = obj.Value.Should().BeOfType<SessionErrorDto>().Subject;
        err.Reason.Should().Be(SessionErrorCodes.SessionRevoked);
    }

    [Fact]
    public async Task GetSession_DeletedAccount_Returns401InvalidToken_NotGenericError()
    {
        _userManagerMock
            .Setup(m => m.FindByIdAsync("ghost"))
            .ReturnsAsync(new ApplicationUser { Id = "ghost", DeletedAt = DateTime.UtcNow });
        var controller = BuildController("ghost");

        var result = await controller.GetSession();

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        obj.Value.Should().BeOfType<SessionErrorDto>()
            .Subject.Reason.Should().Be(SessionErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task GetSession_UnknownSubject_Returns401InvalidToken()
    {
        _userManagerMock.Setup(m => m.FindByIdAsync("nobody")).ReturnsAsync((ApplicationUser?)null);
        var controller = BuildController("nobody");

        var result = await controller.GetSession();

        result.Should().BeOfType<ObjectResult>()
            .Subject.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task GetSession_CannotSignIn_Returns401InvalidToken()
    {
        SetupExistingUser("locked");
        _signInManagerMock.Setup(s => s.CanSignInAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(false);
        var controller = BuildController("locked");

        var result = await controller.GetSession();

        result.Should().BeOfType<ObjectResult>()
            .Subject.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task GetSession_NoSession_Returns200NotAuthenticated_NeverGeneric500()
    {
        SetupExistingUser("user-3");
        // No session seeded.
        var controller = BuildController("user-3");

        var result = await controller.GetSession();

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<SessionTruthDto>().Subject;
        dto.Authenticated.Should().BeFalse();
        dto.Revoked.Should().BeFalse();
    }

    [Fact]
    public async Task GetSession_MissingSubjectClaim_Returns401()
    {
        var controller = BuildController(subject: null);

        var result = await controller.GetSession();

        result.Should().BeOfType<ObjectResult>()
            .Subject.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task Transient503_DoesNotCollapseTo401()
    {
        // #1861 conflation guard: a transient backend failure (here, the data
        // store throwing) MUST surface as 503 temporarily_unavailable so the
        // client retries — it must NEVER come back as a 401 sign-out.
        SetupExistingUser("user-4");
        // Dispose the context so SessionService.ResolveSessionTruthAsync throws
        // when it touches the store — a stand-in for an upstream/dependency blip.
        _context.Dispose();
        var controller = BuildController("user-4");

        var result = await controller.GetSession();

        var obj = result.Should().BeOfType<ObjectResult>().Subject;
        obj.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        obj.StatusCode.Should().NotBe(StatusCodes.Status401Unauthorized);
        obj.Value.Should().BeOfType<SessionErrorDto>()
            .Subject.Reason.Should().Be(SessionErrorCodes.TemporarilyUnavailable);
        controller.Response.Headers.RetryAfter.ToString().Should().Be("5");
    }

    private static Mock<UserManager<ApplicationUser>> MockUserManager()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        return new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
    }

    private static Mock<SignInManager<ApplicationUser>> MockSignInManager(UserManager<ApplicationUser> userManager)
    {
        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
        return new Mock<SignInManager<ApplicationUser>>(
            userManager, contextAccessor.Object, claimsFactory.Object, null!, null!, null!, null!);
    }
}
