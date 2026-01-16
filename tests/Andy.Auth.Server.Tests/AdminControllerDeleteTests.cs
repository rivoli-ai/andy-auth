using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using System.Security.Claims;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Tests for AdminController user deletion functionality.
/// </summary>
public class AdminControllerDeleteTests
{
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ILogger<AdminController>> _mockLogger;
    private readonly Mock<IOpenIddictApplicationManager> _mockApplicationManager;
    private readonly Mock<IOpenIddictTokenManager> _mockTokenManager;
    private readonly Mock<IOpenIddictAuthorizationManager> _mockAuthorizationManager;
    private readonly AdminController _controller;

    public AdminControllerDeleteTests()
    {
        _mockUserManager = MockUserManager();
        _mockAuditService = new Mock<IAuditService>();
        _mockLogger = new Mock<ILogger<AdminController>>();
        _mockApplicationManager = new Mock<IOpenIddictApplicationManager>();
        _mockTokenManager = new Mock<IOpenIddictTokenManager>();
        _mockAuthorizationManager = new Mock<IOpenIddictAuthorizationManager>();

        // Create a real DbContext with in-memory database
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        var dbContext = new ApplicationDbContext(options);

        _controller = new AdminController(
            dbContext,
            _mockUserManager.Object,
            _mockApplicationManager.Object,
            _mockTokenManager.Object,
            _mockAuthorizationManager.Object,
            _mockAuditService.Object,
            _mockLogger.Object);

        // Setup controller context with authenticated user
        var httpContext = new DefaultHttpContext();
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());
    }

    [Fact]
    public async Task DeleteUser_SelfDeletion_ReturnsError()
    {
        // Arrange
        var currentUserId = "current-admin-id";
        var user = new ApplicationUser
        {
            Id = currentUserId,
            Email = "admin@example.com",
            UserName = "admin@example.com",
            IsSystemUser = false
        };

        // Setup claims for current user
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, currentUserId),
            new Claim(ClaimTypes.Email, "admin@example.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        _controller.ControllerContext.HttpContext.User = claimsPrincipal;

        _mockUserManager.Setup(m => m.FindByIdAsync(currentUserId))
            .ReturnsAsync(user);

        // Act
        var result = await _controller.DeleteUser(currentUserId);

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Users", redirectResult.ActionName);
        Assert.Equal("You cannot delete your own account.", _controller.TempData["ErrorMessage"]);
    }

    [Fact]
    public async Task DeleteUser_SystemUser_ReturnsError()
    {
        // Arrange
        var systemUser = new ApplicationUser
        {
            Id = "system-user-id",
            Email = "system@example.com",
            UserName = "system@example.com",
            IsSystemUser = true
        };

        // Setup claims for different current user
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, "other-admin-id"),
            new Claim(ClaimTypes.Email, "other-admin@example.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        _controller.ControllerContext.HttpContext.User = claimsPrincipal;

        _mockUserManager.Setup(m => m.FindByIdAsync("system-user-id"))
            .ReturnsAsync(systemUser);

        // Act
        var result = await _controller.DeleteUser("system-user-id");

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Users", redirectResult.ActionName);
        Assert.Contains("System users are protected", _controller.TempData["ErrorMessage"]?.ToString());
    }

    [Fact]
    public async Task DeleteUser_OtherUser_SoftDeletesSuccessfully()
    {
        // Arrange
        var userToDelete = new ApplicationUser
        {
            Id = "user-to-delete-id",
            Email = "user@example.com",
            UserName = "user@example.com",
            IsSystemUser = false,
            IsActive = true
        };

        // Setup claims for different current user (admin)
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, "admin-id"),
            new Claim(ClaimTypes.Email, "admin@example.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        _controller.ControllerContext.HttpContext.User = claimsPrincipal;

        _mockUserManager.Setup(m => m.FindByIdAsync("user-to-delete-id"))
            .ReturnsAsync(userToDelete);

        _mockUserManager.Setup(m => m.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        _mockAuditService.Setup(a => a.LogAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.DeleteUser("user-to-delete-id");

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Users", redirectResult.ActionName);
        Assert.Contains("has been deleted", _controller.TempData["SuccessMessage"]?.ToString());

        // Verify user was soft-deleted
        Assert.NotNull(userToDelete.DeletedAt);
        Assert.False(userToDelete.IsActive);
    }

    [Fact]
    public async Task DeleteUser_NonExistentUser_ReturnsNotFound()
    {
        // Arrange
        _mockUserManager.Setup(m => m.FindByIdAsync("non-existent-id"))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.DeleteUser("non-existent-id");

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    private static Mock<UserManager<ApplicationUser>> MockUserManager()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        return new Mock<UserManager<ApplicationUser>>(
            store.Object, null, null, null, null, null, null, null, null);
    }
}
