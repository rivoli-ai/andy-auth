using System.Net;
using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;

namespace Andy.Auth.Server.Tests.Services;

public sealed class InteractiveSessionCookieEventsTests : IDisposable
{
    private readonly ApplicationDbContext _dbContext;
    private readonly SessionService _sessionService;
    private readonly InteractiveSessionCookieEvents _events;

    public InteractiveSessionCookieEventsTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"InteractiveCookie_{Guid.NewGuid():N}")
            .Options;
        _dbContext = new ApplicationDbContext(options);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SessionManagement:MaxConcurrentSessions"] = "5"
            })
            .Build();

        _sessionService = new SessionService(
            _dbContext,
            Mock.Of<ILogger<SessionService>>(),
            configuration);
        _events = new InteractiveSessionCookieEvents(
            _sessionService,
            Mock.Of<ILogger<InteractiveSessionCookieEvents>>());
    }

    public void Dispose() => _dbContext.Dispose();

    [Fact]
    public async Task SigningIn_CreatesServerSessionBeforeCookieIssuance()
    {
        var context = CreateContext("user-1", "session-1");

        await _events.SigningIn(context);

        var session = await _dbContext.UserSessions.SingleAsync();
        session.UserId.Should().Be("user-1");
        session.SessionId.Should().Be("session-1");
        session.IpAddress.Should().Be("127.0.0.1");
        session.UserAgent.Should().Be("TestBrowser/1.0");
    }

    [Fact]
    public async Task SigningIn_ExistingActiveSession_DoesNotCreateDuplicate()
    {
        await _sessionService.CreateSessionAsync(
            "user-1", "session-1", "127.0.0.1", "TestBrowser/1.0");

        await _events.SigningIn(CreateContext("user-1", "session-1"));

        (await _dbContext.UserSessions.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task SigningIn_RevokedSession_RefusesCookieRefresh()
    {
        await _sessionService.CreateSessionAsync(
            "user-1", "session-1", "127.0.0.1", "TestBrowser/1.0");
        await _sessionService.RevokeSessionByIdAsync("session-1", "Test revocation");

        var act = () => _events.SigningIn(CreateContext("user-1", "session-1"));

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Theory]
    [InlineData(null, "session-1")]
    [InlineData("user-1", null)]
    public async Task SigningIn_MissingBindingClaim_RefusesCookie(
        string? userId, string? sessionId)
    {
        var act = () => _events.SigningIn(CreateContext(userId, sessionId));

        await act.Should().ThrowAsync<InvalidOperationException>();
        (await _dbContext.UserSessions.CountAsync()).Should().Be(0);
    }

    private static CookieSigningInContext CreateContext(
        string? userId, string? sessionId)
    {
        var claims = new List<Claim>();
        if (userId is not null)
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
        }

        if (sessionId is not null)
        {
            claims.Add(new Claim(AndyAuthSignInManager.SessionIdClaimType, sessionId));
        }

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Loopback;
        httpContext.Request.Headers.UserAgent = "TestBrowser/1.0";

        return new CookieSigningInContext(
            httpContext,
            new AuthenticationScheme(
                "Identity.Application",
                "Identity.Application",
                typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(),
            new ClaimsPrincipal(new ClaimsIdentity(claims, "Identity.Application")),
            new AuthenticationProperties(),
            new CookieOptions());
    }
}
