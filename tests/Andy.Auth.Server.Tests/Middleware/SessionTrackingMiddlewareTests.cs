using Andy.Auth.Server.Data;
using Andy.Auth.Server.Middleware;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;

namespace Andy.Auth.Server.Tests.Middleware;

public class SessionTrackingMiddlewareTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly SessionService _sessionService;
    private readonly Mock<ILogger<SessionTrackingMiddleware>> _loggerMock;
    private readonly IMemoryCache _memoryCache;
    private bool _nextCalled;

    public SessionTrackingMiddlewareTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        var sessionLoggerMock = new Mock<ILogger<SessionService>>();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SessionManagement:MaxConcurrentSessions"] = "5"
            })
            .Build();

        _sessionService = new SessionService(_context, sessionLoggerMock.Object, config);
        _loggerMock = new Mock<ILogger<SessionTrackingMiddleware>>();
        _memoryCache = new MemoryCache(new MemoryCacheOptions());
    }

    public void Dispose()
    {
        _context.Dispose();
        _memoryCache.Dispose();
    }

    private SessionTrackingMiddleware CreateMiddleware()
    {
        _nextCalled = false;
        return new SessionTrackingMiddleware(
            context =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            _loggerMock.Object);
    }

    private HttpContext CreateHttpContext(bool authenticated = false, string? sessionId = null, string? userId = null, string path = "/")
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = path;
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        httpContext.Request.Headers.UserAgent = "TestBrowser/1.0";

        if (authenticated)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, userId ?? "test-user-id")
            };

            if (sessionId != null)
            {
                claims.Add(new Claim("session_id", sessionId));
            }

            var identity = new ClaimsIdentity(claims, "Test");
            httpContext.User = new ClaimsPrincipal(identity);
        }

        // Setup service provider with required services
        var services = new ServiceCollection();
        services.AddSingleton(_memoryCache);
        httpContext.RequestServices = services.BuildServiceProvider();

        return httpContext;
    }

    // ==================== Skip Path Tests ====================

    [Theory]
    [InlineData("/css/style.css")]
    [InlineData("/js/app.js")]
    [InlineData("/images/logo.png")]
    [InlineData("/favicon.ico")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/health")]
    [InlineData("/connect/token")]
    public async Task InvokeAsync_SkipPaths_PassesThroughWithoutTracking(string path)
    {
        // Arrange
        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(authenticated: true, sessionId: "test-session", path: path);

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
        // No session should be created for skip paths
        var sessions = await _context.UserSessions.ToListAsync();
        sessions.Should().BeEmpty();
    }

    [Fact]
    public async Task InvokeAsync_NormalPath_ProcessesTracking()
    {
        // Arrange
        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(authenticated: true, sessionId: "test-session", userId: "user-1", path: "/dashboard");

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    // ==================== Unauthenticated User Tests ====================

    [Fact]
    public async Task InvokeAsync_UnauthenticatedUser_PassesThroughWithoutTracking()
    {
        // Arrange
        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(authenticated: false, path: "/dashboard");

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
        var sessions = await _context.UserSessions.ToListAsync();
        sessions.Should().BeEmpty();
    }

    // ==================== Session Creation Tests ====================

    [Fact]
    public async Task InvokeAsync_AuthenticatedUserWithNoSession_CreatesSession()
    {
        // Arrange
        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: "new-session-id",
            userId: "user-1",
            path: "/dashboard");

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
        var session = await _context.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == "new-session-id");
        session.Should().NotBeNull();
        session!.UserId.Should().Be("user-1");
    }

    [Fact]
    public async Task InvokeAsync_SessionCreation_IncludesIpAndUserAgent()
    {
        // Arrange
        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: "session-with-metadata",
            userId: "user-1",
            path: "/dashboard");

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        var session = await _context.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == "session-with-metadata");
        session.Should().NotBeNull();
        session!.IpAddress.Should().Be("127.0.0.1");
        session.UserAgent.Should().Be("TestBrowser/1.0");
    }

    // ==================== Session Validation Tests ====================

    [Fact]
    public async Task InvokeAsync_ValidExistingSession_UpdatesActivity()
    {
        // Arrange
        var sessionId = "existing-session";
        await _sessionService.CreateSessionAsync("user-1", sessionId, "127.0.0.1", "Browser");

        // Clear the cache to allow activity update
        _memoryCache.Remove($"session:last-activity:{sessionId}");

        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: sessionId,
            userId: "user-1",
            path: "/dashboard");

        var originalActivity = (await _context.UserSessions.FirstAsync(s => s.SessionId == sessionId)).LastActivity;

        // Add small delay to ensure timestamp difference
        await Task.Delay(10);

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
        var updatedSession = await _context.UserSessions.FirstAsync(s => s.SessionId == sessionId);
        updatedSession.LastActivity.Should().BeOnOrAfter(originalActivity);
    }

    [Fact]
    public async Task InvokeAsync_RevokedSession_SignsOutUser()
    {
        // Arrange
        var sessionId = "revoked-session";
        await _sessionService.CreateSessionAsync("user-1", sessionId, "127.0.0.1", "Browser");
        await _sessionService.RevokeSessionByIdAsync(sessionId, "Test revocation");

        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: sessionId,
            userId: "user-1",
            path: "/dashboard");

        // Mock authentication to verify sign-out behavior
        var authServiceMock = new Mock<IAuthenticationService>();
        var services = new ServiceCollection();
        services.AddSingleton(_memoryCache);
        services.AddSingleton(authServiceMock.Object);
        httpContext.RequestServices = services.BuildServiceProvider();

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert - For web request, should redirect
        httpContext.Response.StatusCode.Should().Be(302);
        _nextCalled.Should().BeFalse();
    }

    [Fact]
    public async Task InvokeAsync_RevokedSessionApiRequest_Returns401()
    {
        // Arrange
        var sessionId = "revoked-api-session";
        await _sessionService.CreateSessionAsync("user-1", sessionId, "127.0.0.1", "Browser");
        await _sessionService.RevokeSessionByIdAsync(sessionId, "Test revocation");

        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: sessionId,
            userId: "user-1",
            path: "/api/users");

        httpContext.Request.Headers.Accept = "application/json";

        var authServiceMock = new Mock<IAuthenticationService>();
        var services = new ServiceCollection();
        services.AddSingleton(_memoryCache);
        services.AddSingleton(authServiceMock.Object);
        httpContext.RequestServices = services.BuildServiceProvider();

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        httpContext.Response.StatusCode.Should().Be(401);
        _nextCalled.Should().BeFalse();
    }

    // ==================== Activity Throttling Tests ====================

    [Fact]
    public async Task InvokeAsync_RecentActivity_DoesNotUpdateDatabase()
    {
        // Arrange
        var sessionId = "throttled-session";
        await _sessionService.CreateSessionAsync("user-1", sessionId, "127.0.0.1", "Browser");

        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: sessionId,
            userId: "user-1",
            path: "/dashboard");

        // First call - should update activity and cache
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        var firstActivity = (await _context.UserSessions.FirstAsync(s => s.SessionId == sessionId)).LastActivity;

        // Second call - should be throttled
        await Task.Delay(10);
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        var secondActivity = (await _context.UserSessions.FirstAsync(s => s.SessionId == sessionId)).LastActivity;
        // Should be the same because it was throttled
        secondActivity.Should().Be(firstActivity);
    }

    // ==================== Missing Session ID Tests ====================

    [Fact]
    public async Task InvokeAsync_AuthenticatedButNoSessionId_PassesThrough()
    {
        // Arrange
        var middleware = CreateMiddleware();

        // Create context with authentication but no session_id claim
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "user-1")
            // No session_id claim
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext
        {
            User = principal
        };
        httpContext.Request.Path = "/dashboard";

        var services = new ServiceCollection();
        services.AddSingleton(_memoryCache);
        httpContext.RequestServices = services.BuildServiceProvider();

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
        // No session should be created without session ID
        var sessions = await _context.UserSessions.ToListAsync();
        sessions.Should().BeEmpty();
    }

    [Fact]
    public async Task InvokeAsync_AuthenticatedButNoUserId_PassesThrough()
    {
        // Arrange
        var middleware = CreateMiddleware();

        // Create context with session_id but no user ID
        var claims = new List<Claim>
        {
            new("session_id", "orphan-session")
            // No NameIdentifier claim
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext
        {
            User = principal
        };
        httpContext.Request.Path = "/dashboard";

        var services = new ServiceCollection();
        services.AddSingleton(_memoryCache);
        httpContext.RequestServices = services.BuildServiceProvider();

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        _nextCalled.Should().BeTrue();
        var sessions = await _context.UserSessions.ToListAsync();
        sessions.Should().BeEmpty();
    }

    // ==================== API Path Detection Tests ====================

    [Theory]
    [InlineData("/api/users", true)]
    [InlineData("/connect/token", true)]
    [InlineData("/dashboard", false)]
    [InlineData("/account/login", false)]
    public async Task InvokeAsync_DetectsApiRequests(string path, bool isApiPath)
    {
        // This test verifies API detection by checking the redirect behavior
        // API requests get 401, web requests get redirected

        // Arrange
        var sessionId = $"revoked-session-{path.Replace("/", "-")}";
        await _sessionService.CreateSessionAsync("user-1", sessionId, "127.0.0.1", "Browser");
        await _sessionService.RevokeSessionByIdAsync(sessionId, "Test");

        var middleware = CreateMiddleware();
        var httpContext = CreateHttpContext(
            authenticated: true,
            sessionId: sessionId,
            userId: "user-1",
            path: path);

        if (isApiPath)
        {
            httpContext.Request.Headers.Accept = "application/json";
        }

        var authServiceMock = new Mock<IAuthenticationService>();
        var services = new ServiceCollection();
        services.AddSingleton(_memoryCache);
        services.AddSingleton(authServiceMock.Object);
        httpContext.RequestServices = services.BuildServiceProvider();

        // Act
        await middleware.InvokeAsync(httpContext, _sessionService, _context);

        // Assert
        if (isApiPath)
        {
            httpContext.Response.StatusCode.Should().Be(401);
        }
        else
        {
            httpContext.Response.StatusCode.Should().Be(302);
        }
    }
}

// Mock IAuthenticationService for testing sign-out
public interface IAuthenticationService
{
    Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties);
}

public class AuthenticationProperties { }
