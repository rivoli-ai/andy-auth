using System.Collections.Immutable;
using System.Security.Claims;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Unit tests for the AuthorizationController class
/// </summary>
public class AuthorizationControllerTests
{
    private readonly Mock<IOpenIddictApplicationManager> _mockAppManager;
    private readonly Mock<IOpenIddictAuthorizationManager> _mockAuthorizationManager;
    private readonly Mock<IOpenIddictScopeManager> _mockScopeManager;
    private readonly Mock<SignInManager<ApplicationUser>> _mockSignInManager;
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<ITokenExchangePolicy> _mockTokenExchangePolicy;
    private readonly Mock<ISubjectTokenValidator> _mockSubjectTokenValidator;
    private readonly Mock<ILogger<AuthorizationController>> _mockLogger;
    private readonly ApplicationDbContext _dbContext;
    private readonly AuthorizationController _controller;
    private readonly DefaultHttpContext _httpContext;

    public AuthorizationControllerTests()
    {
        _mockAppManager = new Mock<IOpenIddictApplicationManager>();
        _mockAuthorizationManager = new Mock<IOpenIddictAuthorizationManager>();
        _mockScopeManager = new Mock<IOpenIddictScopeManager>();
        _mockUserManager = MockUserManager();
        _mockSignInManager = MockSignInManager(_mockUserManager.Object);
        _mockTokenExchangePolicy = new Mock<ITokenExchangePolicy>();
        _mockSubjectTokenValidator = new Mock<ISubjectTokenValidator>();
        _mockLogger = new Mock<ILogger<AuthorizationController>>();

        // Create in-memory database for testing
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: $"TestDb_{Guid.NewGuid()}")
            .Options;
        _dbContext = new ApplicationDbContext(options);

        _controller = new AuthorizationController(
            _mockAppManager.Object,
            _mockAuthorizationManager.Object,
            _mockScopeManager.Object,
            _mockSignInManager.Object,
            _mockUserManager.Object,
            _dbContext,
            _mockTokenExchangePolicy.Object,
            _mockSubjectTokenValidator.Object,
            new TokenClaimsPrincipalFactory(
                _mockSignInManager.Object,
                _mockUserManager.Object,
                _mockAppManager.Object,
                _mockAuthorizationManager.Object,
                _mockScopeManager.Object,
                new RolePermissionResolver(
                    Microsoft.Extensions.Options.Options.Create(new RolePermissionOptions())),
                _dbContext),
            new DcrClientGate(_dbContext),
            TestConsent.CreateConsentTicketService(),
            _mockLogger.Object);

        _httpContext = new DefaultHttpContext();
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = _httpContext
        };
    }

    #region Userinfo Endpoint Tests

    [Fact]
    public async Task Userinfo_UserNotFound_ReturnsChallengeResult()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new Claim(Claims.Subject, "nonexistent-user-id")
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        _httpContext.User = principal;
        _mockUserManager.Setup(m => m.FindByIdAsync("nonexistent-user-id"))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.Userinfo();

        // Assert
        var challengeResult = Assert.IsType<ChallengeResult>(result);
        Assert.Contains(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, challengeResult.AuthenticationSchemes);
    }

    [Fact]
    public async Task Userinfo_ValidUser_ReturnsUserClaims()
    {
        // Arrange
        var userId = "test-user-id";
        var user = new ApplicationUser
        {
            Id = userId,
            Email = "test@example.com",
            UserName = "test@example.com",
            FullName = "Test User",
            ProfilePictureUrl = "https://example.com/photo.jpg",
            EmailConfirmed = true
        };

        var claims = new List<Claim>
        {
            new Claim(Claims.Subject, userId)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Set scopes using OpenIddict's SetScopes extension to ensure proper claim type
        principal.SetScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        _httpContext.User = principal;
        _mockUserManager.Setup(m => m.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(m => m.GetUserIdAsync(user))
            .ReturnsAsync(userId);
        _mockUserManager.Setup(m => m.GetEmailAsync(user))
            .ReturnsAsync(user.Email);
        _mockUserManager.Setup(m => m.IsEmailConfirmedAsync(user))
            .ReturnsAsync(user.EmailConfirmed);
        _mockUserManager.Setup(m => m.GetUserNameAsync(user))
            .ReturnsAsync(user.UserName);
        _mockUserManager.Setup(m => m.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "User" });

        // Act
        var result = await _controller.Userinfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claimsDict = Assert.IsType<Dictionary<string, object>>(okResult.Value);

        Assert.Equal(userId, claimsDict[Claims.Subject]);
        Assert.Equal(user.Email, claimsDict[Claims.Email]);
        Assert.Equal(user.FullName, claimsDict[Claims.Name]);
    }

    [Fact]
    public async Task Userinfo_WithEmailScopeOnly_ReturnsOnlyEmailClaims()
    {
        // Arrange
        var userId = "test-user-id";
        var user = new ApplicationUser
        {
            Id = userId,
            Email = "test@example.com",
            UserName = "test@example.com",
            FullName = "Test User",
            EmailConfirmed = true
        };

        var claims = new List<Claim>
        {
            new Claim(Claims.Subject, userId)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Set scopes using OpenIddict's SetScopes extension to ensure proper claim type
        principal.SetScopes(Scopes.Email);

        _httpContext.User = principal;
        _mockUserManager.Setup(m => m.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(m => m.GetUserIdAsync(user))
            .ReturnsAsync(userId);
        _mockUserManager.Setup(m => m.GetEmailAsync(user))
            .ReturnsAsync(user.Email);
        _mockUserManager.Setup(m => m.IsEmailConfirmedAsync(user))
            .ReturnsAsync(user.EmailConfirmed);

        // Act
        var result = await _controller.Userinfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claimsDict = Assert.IsType<Dictionary<string, object>>(okResult.Value);

        Assert.Equal(userId, claimsDict[Claims.Subject]);
        Assert.True(claimsDict.ContainsKey(Claims.Email) || claimsDict.ContainsKey("email"),
            "Expected email claim to be present");
        Assert.False(claimsDict.ContainsKey(Claims.Name));
        Assert.False(claimsDict.ContainsKey(Claims.Role));
    }

    [Fact]
    public async Task Userinfo_WithProfileScope_ReturnsProfileClaims()
    {
        // Arrange
        var userId = "test-user-id";
        var user = new ApplicationUser
        {
            Id = userId,
            Email = "test@example.com",
            UserName = "testuser",
            FullName = "Test User",
            ProfilePictureUrl = "https://example.com/photo.jpg"
        };

        var claims = new List<Claim>
        {
            new Claim(Claims.Subject, userId)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Set scopes using OpenIddict's SetScopes extension to ensure proper claim type
        principal.SetScopes(Scopes.Profile);

        _httpContext.User = principal;
        _mockUserManager.Setup(m => m.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(m => m.GetUserIdAsync(user))
            .ReturnsAsync(userId);
        _mockUserManager.Setup(m => m.GetUserNameAsync(user))
            .ReturnsAsync(user.UserName);

        // Act
        var result = await _controller.Userinfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claimsDict = Assert.IsType<Dictionary<string, object>>(okResult.Value);

        Assert.Equal(user.FullName, claimsDict[Claims.Name]);
        Assert.Equal(user.UserName, claimsDict[Claims.PreferredUsername]);
        Assert.Equal(user.ProfilePictureUrl, claimsDict["profile_picture_url"]);
    }

    [Fact]
    public async Task Userinfo_WithRolesScope_ReturnsRoleClaims()
    {
        // Arrange
        var userId = "test-user-id";
        var user = new ApplicationUser
        {
            Id = userId,
            Email = "admin@example.com",
            UserName = "admin@example.com"
        };

        var userRoles = new List<string> { "Admin", "User" };

        var claims = new List<Claim>
        {
            new Claim(Claims.Subject, userId)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Set scopes using OpenIddict's SetScopes extension to ensure proper claim type
        principal.SetScopes(Scopes.Roles);

        _httpContext.User = principal;
        _mockUserManager.Setup(m => m.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(m => m.GetUserIdAsync(user))
            .ReturnsAsync(userId);
        _mockUserManager.Setup(m => m.GetRolesAsync(user))
            .ReturnsAsync(userRoles);

        // Act
        var result = await _controller.Userinfo();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var claimsDict = Assert.IsType<Dictionary<string, object>>(okResult.Value);

        var roles = Assert.IsType<List<string>>(claimsDict[Claims.Role]);
        Assert.Contains("Admin", roles);
        Assert.Contains("User", roles);
    }

    #endregion

    #region Logout Endpoint Tests

    [Fact]
    public async Task Logout_SignsOutUser()
    {
        // Arrange
        _mockSignInManager.Setup(m => m.SignOutAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Logout();

        // Assert
        _mockSignInManager.Verify(m => m.SignOutAsync(), Times.Once);
    }

    [Fact]
    public async Task Logout_WithoutPostLogoutRedirectUri_RedirectsToHome()
    {
        // Arrange
        _mockSignInManager.Setup(m => m.SignOutAsync())
            .Returns(Task.CompletedTask);

        // No OpenIddict request in context (no post_logout_redirect_uri)

        // Act
        var result = await _controller.Logout();

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Equal("/", redirectResult.Url);
    }

    #endregion


    #region Consent Bypass (andy-auth#124)

    /// <summary>
    /// Drives /connect/authorize for an explicit-consent client with the given
    /// query string, standing in for the OpenIddict transaction the ASP.NET
    /// host would normally have attached.
    /// </summary>
    private async Task<IActionResult> AuthorizeWithQueryAsync(
        ApplicationUser user,
        Dictionary<string, StringValues> query)
    {
        var request = new OpenIddictRequest
        {
            ClientId = "test-client",
            RedirectUri = "https://client.example/callback",
            Scope = "openid profile email",
            ResponseType = "code",
        };

        _httpContext.Features.Set(new OpenIddictServerAspNetCoreFeature
        {
            Transaction = new OpenIddictServerTransaction { Request = request }
        });
        _httpContext.Request.Path = "/connect/authorize";
        _httpContext.Request.Query = new QueryCollection(query);

        // The user is signed in via the Identity cookie.
        var identityPrincipal = new ClaimsPrincipal(
            new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, user.Id) },
                IdentityConstants.ApplicationScheme));

        var authService = new Mock<IAuthenticationService>();
        authService
            .Setup(x => x.AuthenticateAsync(_httpContext, IdentityConstants.ApplicationScheme))
            .ReturnsAsync(AuthenticateResult.Success(
                new AuthenticationTicket(identityPrincipal, IdentityConstants.ApplicationScheme)));

        var services = new ServiceCollection();
        services.AddSingleton(authService.Object);
        _httpContext.RequestServices = services.BuildServiceProvider();

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.GetUserIdAsync(user)).ReturnsAsync(user.Id);
        _mockUserManager.Setup(m => m.GetRolesAsync(user)).ReturnsAsync(new List<string>());

        var application = new object();
        _mockAppManager.Setup(m => m.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        _mockAppManager.Setup(m => m.GetIdAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("app-1");
        _mockAppManager.Setup(m => m.GetConsentTypeAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ConsentTypes.Explicit);
        _mockAuthorizationManager.Setup(m => m.FindAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
            .Returns(EmptyAsync<object>());
        _mockScopeManager.Setup(m => m.ListResourcesAsync(
                It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
            .Returns(EmptyAsync<string>());
        _mockSignInManager.Setup(m => m.CreateUserPrincipalAsync(user))
            .ReturnsAsync(() => new ClaimsPrincipal(
                new ClaimsIdentity(Array.Empty<Claim>(), "Identity.Application", Claims.Name, Claims.Role)));

        return await _controller.Authorize();
    }

    private static async IAsyncEnumerable<T> EmptyAsync<T>()
    {
        await Task.CompletedTask;
        yield break;
    }

    private static ApplicationUser ConsentTestUser() => new()
    {
        Id = "user-1",
        Email = "user@test.local",
        UserName = "user@test.local",
        IsActive = true,
    };

    [Fact]
    public async Task Authorize_ForgedConsentGrantedMarker_StillRedirectsToConsent()
    {
        // The bug: `consent_granted=true` was read straight off the query
        // string as proof of approval, and the whole authorization request is
        // client-controlled — so appending it skipped the consent screen.
        var result = await AuthorizeWithQueryAsync(ConsentTestUser(), new()
        {
            ["consent_granted"] = "true",
        });

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith("/Consent", redirect.Url);
    }

    [Fact]
    public async Task Authorize_ForgedConsentTokenValue_StillRedirectsToConsent()
    {
        var result = await AuthorizeWithQueryAsync(ConsentTestUser(), new()
        {
            ["consent_token"] = "not-a-real-ticket",
        });

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith("/Consent", redirect.Url);
    }

    [Fact]
    public async Task Authorize_NoConsentEvidence_RedirectsToConsent()
    {
        var result = await AuthorizeWithQueryAsync(ConsentTestUser(), new());

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith("/Consent", redirect.Url);
    }

    [Fact]
    public async Task Authorize_ValidConsentTicket_IssuesTheCode()
    {
        var user = ConsentTestUser();
        var ticket = TestConsent.CreateConsentTicketService()
            .Issue(user.Id, "test-client", "https://client.example/callback",
                new[] { "openid", "profile", "email" });

        var result = await AuthorizeWithQueryAsync(user, new()
        {
            ["consent_token"] = ticket,
        });

        Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
    }

    [Fact]
    public async Task Authorize_PartialConsentTicket_IssuesOnlyTheApprovedScopes()
    {
        // Every branch used to sign in with request.GetScopes() wholesale, so
        // unticking a scope on the consent screen still produced a fully-scoped
        // token.
        var user = ConsentTestUser();
        var ticket = TestConsent.CreateConsentTicketService()
            .Issue(user.Id, "test-client", "https://client.example/callback",
                new[] { "openid" });

        var result = await AuthorizeWithQueryAsync(user, new()
        {
            ["consent_token"] = ticket,
        });

        var signIn = Assert.IsType<Microsoft.AspNetCore.Mvc.SignInResult>(result);
        var scopes = signIn.Principal!.GetScopes();
        Assert.Equal(new[] { "openid" }, scopes);
    }

    #endregion

    #region Helper Methods

    private static Mock<UserManager<ApplicationUser>> MockUserManager()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        return new Mock<UserManager<ApplicationUser>>(
            store.Object, null, null, null, null, null, null, null, null);
    }

    private static Mock<SignInManager<ApplicationUser>> MockSignInManager(UserManager<ApplicationUser> userManager)
    {
        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();

        return new Mock<SignInManager<ApplicationUser>>(
            userManager,
            contextAccessor.Object,
            claimsFactory.Object,
            null, null, null, null);
    }

    #endregion
}
