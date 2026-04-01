using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;

namespace Andy.Auth.Server.Tests;

public class SessionControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<ILogger<SessionController>> _loggerMock;
    private readonly Mock<ILogger<SessionService>> _sessionLoggerMock;
    private readonly SessionService _sessionService;
    private readonly SessionController _controller;

    public SessionControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _loggerMock = new Mock<ILogger<SessionController>>();
        _sessionLoggerMock = new Mock<ILogger<SessionService>>();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SessionManagement:MaxConcurrentSessions"] = "5"
            })
            .Build();

        _sessionService = new SessionService(_context, _sessionLoggerMock.Object, config);

        _controller = new SessionController(
            _sessionService,
            _userManagerMock.Object,
            _loggerMock.Object);

        // Setup HttpContext with user claims
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "user-1"),
            new("session_id", "current-session")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext { User = principal };
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());

        _userManagerMock.Setup(x => x.GetUserId(principal)).Returns("user-1");
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== Index Tests ====================

    [Fact]
    public async Task Index_ReturnsViewWithSessions()
    {
        // Arrange
        await _sessionService.CreateSessionAsync("user-1", "session-1", "192.168.1.1", "Chrome/Windows");
        await _sessionService.CreateSessionAsync("user-1", "session-2", "192.168.1.2", "Safari/Mac");

        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<SessionsViewModel>().Subject;
        model.Sessions.Should().HaveCount(2);
        model.MaxConcurrentSessions.Should().Be(5);
    }

    [Fact]
    public async Task Index_IdentifiesCurrentSession()
    {
        // Arrange
        await _sessionService.CreateSessionAsync("user-1", "other-session", null, null);
        await _sessionService.CreateSessionAsync("user-1", "current-session", null, null);

        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<SessionsViewModel>().Subject;
        var currentSession = model.Sessions.FirstOrDefault(s => s.IsCurrentSession);
        currentSession.Should().NotBeNull();
        currentSession!.SessionId.Should().Be("current-session");
    }

    [Fact]
    public async Task Index_ReturnsEmptyListForNoSessions()
    {
        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<SessionsViewModel>().Subject;
        model.Sessions.Should().BeEmpty();
    }

    [Fact]
    public async Task Index_ExcludesRevokedSessions()
    {
        // Arrange
        await _sessionService.CreateSessionAsync("user-1", "active-session", null, null);
        var revokedSession = await _sessionService.CreateSessionAsync("user-1", "revoked-session", null, null);
        await _sessionService.RevokeSessionByIdAsync("revoked-session", "Test");

        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<SessionsViewModel>().Subject;
        model.Sessions.Should().ContainSingle();
        model.Sessions[0].SessionId.Should().Be("active-session");
    }

    // ==================== Revoke Tests ====================

    [Fact]
    public async Task Revoke_RevokesSessionAndRedirects()
    {
        // Arrange
        var session = await _sessionService.CreateSessionAsync("user-1", "session-1", null, null);

        // Act
        var result = await _controller.Revoke(session.Id);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        _controller.TempData["Message"].Should().NotBeNull();

        var revokedSession = await _context.UserSessions.FindAsync(session.Id);
        revokedSession!.IsRevoked.Should().BeTrue();
    }

    [Fact]
    public async Task Revoke_ReturnsErrorForNonExistentSession()
    {
        // Act
        var result = await _controller.Revoke(999);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        _controller.TempData["Error"].Should().NotBeNull();
    }

    [Fact]
    public async Task Revoke_CannotRevokeOtherUsersSession()
    {
        // Arrange
        var otherUserSession = await _sessionService.CreateSessionAsync("user-2", "other-session", null, null);

        // Act
        var result = await _controller.Revoke(otherUserSession.Id);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["Error"].Should().NotBeNull();
    }

    // ==================== RevokeAllOther Tests ====================

    [Fact]
    public async Task RevokeAllOther_RevokesAllExceptCurrent()
    {
        // Arrange
        await _sessionService.CreateSessionAsync("user-1", "session-1", null, null);
        await _sessionService.CreateSessionAsync("user-1", "session-2", null, null);
        await _sessionService.CreateSessionAsync("user-1", "current-session", null, null);

        // Act
        var result = await _controller.RevokeAllOther();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        ((string)_controller.TempData["Message"]!).Should().Contain("2 session(s)");

        var activeSessions = await _sessionService.GetActiveSessionsAsync("user-1");
        activeSessions.Should().ContainSingle();
        activeSessions[0].SessionId.Should().Be("current-session");
    }

    [Fact]
    public async Task RevokeAllOther_HandlesNoOtherSessions()
    {
        // Arrange
        await _sessionService.CreateSessionAsync("user-1", "current-session", null, null);

        // Act
        var result = await _controller.RevokeAllOther();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        ((string)_controller.TempData["Message"]!).Should().Contain("0 session(s)");
    }

    [Fact]
    public async Task RevokeAllOther_HandlesNoCurrentSessionId()
    {
        // Arrange - Remove session_id claim
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "user-1")
            // No session_id claim
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext { User = principal };
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());
        _userManagerMock.Setup(x => x.GetUserId(principal)).Returns("user-1");

        // Act
        var result = await _controller.RevokeAllOther();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        _controller.TempData["Error"].Should().NotBeNull();
    }
}
