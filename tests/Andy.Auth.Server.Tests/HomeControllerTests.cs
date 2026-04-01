using Andy.Auth.Server.Controllers;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Andy.Auth.Server.Tests;

public class HomeControllerTests
{
    private readonly HomeController _controller;

    public HomeControllerTests()
    {
        _controller = new HomeController();
    }

    private void SetupUnauthenticatedUser()
    {
        var identity = new ClaimsIdentity(); // Not authenticated
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    private void SetupAuthenticatedUser(string role = "User")
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "user-1"),
            new(ClaimTypes.Email, "user@test.com"),
            new(ClaimTypes.Role, role)
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    // ==================== Index Tests ====================

    [Fact]
    public void Index_UnauthenticatedUser_ReturnsHomeView()
    {
        // Arrange
        SetupUnauthenticatedUser();

        // Act
        var result = _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        viewResult.ViewName.Should().BeNull(); // Default view
    }

    [Fact]
    public void Index_AuthenticatedAdmin_RedirectsToAdminIndex()
    {
        // Arrange
        SetupAuthenticatedUser("Admin");

        // Act
        var result = _controller.Index();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        redirect.ControllerName.Should().Be("Admin");
    }

    [Fact]
    public void Index_AuthenticatedUser_ReturnsUserSuccessView()
    {
        // Arrange
        SetupAuthenticatedUser("User");

        // Act
        var result = _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        viewResult.ViewName.Should().Be("UserSuccess");
    }

    // ==================== UserSuccess Tests ====================

    [Fact]
    public void UserSuccess_ReturnsView()
    {
        // Arrange
        SetupAuthenticatedUser();

        // Act
        var result = _controller.UserSuccess();

        // Assert
        result.Should().BeOfType<ViewResult>();
    }

    // ==================== Error Tests ====================

    [Fact]
    public void Error_ReturnsView()
    {
        // Arrange
        SetupUnauthenticatedUser();

        // Act
        var result = _controller.Error();

        // Assert
        result.Should().BeOfType<ViewResult>();
    }

    // ==================== AccessDenied Tests ====================

    [Fact]
    public void AccessDenied_ReturnsView()
    {
        // Arrange
        SetupUnauthenticatedUser();

        // Act
        var result = _controller.AccessDenied();

        // Assert
        result.Should().BeOfType<ViewResult>();
    }
}
