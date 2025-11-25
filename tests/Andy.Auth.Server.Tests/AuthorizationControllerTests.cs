using System.Collections.Immutable;
using System.Security.Claims;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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
            _dbContext);

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
            new Claim(Claims.Subject, userId),
            new Claim(Claims.Scope, Scopes.Email),
            new Claim(Claims.Scope, Scopes.Profile),
            new Claim(Claims.Scope, Scopes.Roles)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

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
            new Claim(Claims.Subject, userId),
            new Claim(Claims.Scope, Scopes.Email)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

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
            new Claim(Claims.Subject, userId),
            new Claim(Claims.Scope, Scopes.Profile)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

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
            new Claim(Claims.Subject, userId),
            new Claim(Claims.Scope, Scopes.Roles)
        };
        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

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
