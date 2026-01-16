using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Tests for the AccountController class
/// </summary>
public class AccountControllerTests
{
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<SignInManager<ApplicationUser>> _mockSignInManager;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly SessionService _sessionService;
    private readonly Mock<ILogger<AccountController>> _mockLogger;
    private readonly AccountController _controller;

    public AccountControllerTests()
    {
        _mockUserManager = MockUserManager();
        _mockSignInManager = MockSignInManager(_mockUserManager.Object);
        _mockAuditService = new Mock<IAuditService>();
        _sessionService = CreateSessionService();
        _mockLogger = new Mock<ILogger<AccountController>>();

        _controller = new AccountController(
            _mockSignInManager.Object,
            _mockUserManager.Object,
            _mockAuditService.Object,
            _sessionService,
            _mockLogger.Object);

        // Setup controller context for URL helper
        var httpContext = new DefaultHttpContext();
        var mockUrlHelper = new Mock<IUrlHelper>();
        mockUrlHelper
            .Setup(x => x.IsLocalUrl(It.IsAny<string>()))
            .Returns((string url) => !string.IsNullOrEmpty(url) && url.StartsWith('/'));

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
        _controller.Url = mockUrlHelper.Object;
        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());
    }

    #region Login GET Tests

    [Fact]
    public void Login_Get_ReturnsViewResult_WithViewModel()
    {
        // Arrange
        var returnUrl = "/connect/authorize";

        // Act
        var result = _controller.Login(returnUrl);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<LoginViewModel>(viewResult.Model);
        Assert.Equal(returnUrl, model.ReturnUrl);
        Assert.Equal(returnUrl, _controller.ViewData["ReturnUrl"]);
    }

    [Fact]
    public void Login_Get_WithNullReturnUrl_ReturnsViewWithNullReturnUrl()
    {
        // Act
        var result = _controller.Login((string?)null);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<LoginViewModel>(viewResult.Model);
        Assert.Null(model.ReturnUrl);
    }

    #endregion

    #region Login POST Tests

    [Fact]
    public async Task Login_Post_InvalidModelState_ReturnsViewWithModel()
    {
        // Arrange
        var model = new LoginViewModel { Email = "test@example.com" };
        _controller.ModelState.AddModelError("Password", "Required");

        // Act
        var result = await _controller.Login(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
    }

    [Fact]
    public async Task Login_Post_UserNotFound_AddsModelErrorAndReturnsView()
    {
        // Arrange
        var model = new LoginViewModel
        {
            Email = "nonexistent@example.com",
            Password = "Password123!"
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(model.Email))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.Login(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
        Assert.False(_controller.ModelState.IsValid);
        Assert.Contains(_controller.ModelState.Values,
            v => v.Errors.Any(e => e.ErrorMessage == "Invalid login attempt."));
    }

    [Fact]
    public async Task Login_Post_InactiveUser_AddsModelErrorAndReturnsView()
    {
        // Arrange
        var model = new LoginViewModel
        {
            Email = "inactive@example.com",
            Password = "Password123!"
        };

        var inactiveUser = new ApplicationUser
        {
            Email = model.Email,
            IsActive = false
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(model.Email))
            .ReturnsAsync(inactiveUser);

        // Act
        var result = await _controller.Login(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
        Assert.False(_controller.ModelState.IsValid);
        Assert.Contains(_controller.ModelState.Values,
            v => v.Errors.Any(e => e.ErrorMessage == "This account has been disabled."));
    }

    [Fact]
    public async Task Login_Post_SuccessfulLogin_UpdatesLastLoginAndRedirects()
    {
        // Arrange
        var model = new LoginViewModel
        {
            Email = "test@example.com",
            Password = "Password123!",
            RememberMe = true
        };

        var user = new ApplicationUser
        {
            Email = model.Email,
            IsActive = true
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(model.Email))
            .ReturnsAsync(user);

        _mockSignInManager.Setup(m => m.PasswordSignInAsync(user, model.Password, model.RememberMe, true))
            .ReturnsAsync(SignInResult.Success);

        _mockUserManager.Setup(m => m.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.Login(model);

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirectResult.ActionName);
        Assert.Equal("Home", redirectResult.ControllerName);

        _mockUserManager.Verify(m => m.UpdateAsync(It.Is<ApplicationUser>(u => u.LastLoginAt != null)), Times.Once);
    }

    [Fact]
    public async Task Login_Post_SuccessfulLoginWithReturnUrl_RedirectsToReturnUrl()
    {
        // Arrange
        var returnUrl = "/connect/authorize";
        var model = new LoginViewModel
        {
            Email = "test@example.com",
            Password = "Password123!",
            ReturnUrl = returnUrl
        };

        var user = new ApplicationUser
        {
            Email = model.Email,
            IsActive = true
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(model.Email))
            .ReturnsAsync(user);

        _mockSignInManager.Setup(m => m.PasswordSignInAsync(user, model.Password, model.RememberMe, true))
            .ReturnsAsync(SignInResult.Success);

        _mockUserManager.Setup(m => m.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.Login(model);

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Equal(returnUrl, redirectResult.Url);
    }

    [Fact]
    public async Task Login_Post_LockedOutUser_AddsModelErrorAndReturnsView()
    {
        // Arrange
        var model = new LoginViewModel
        {
            Email = "locked@example.com",
            Password = "Password123!"
        };

        var user = new ApplicationUser
        {
            Email = model.Email,
            IsActive = true
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(model.Email))
            .ReturnsAsync(user);

        _mockSignInManager.Setup(m => m.PasswordSignInAsync(user, model.Password, model.RememberMe, true))
            .ReturnsAsync(SignInResult.LockedOut);

        // Act
        var result = await _controller.Login(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
        Assert.False(_controller.ModelState.IsValid);
        Assert.Contains(_controller.ModelState.Values,
            v => v.Errors.Any(e => e.ErrorMessage.Contains("locked out")));
    }

    [Fact]
    public async Task Login_Post_FailedLogin_AddsModelErrorAndReturnsView()
    {
        // Arrange
        var model = new LoginViewModel
        {
            Email = "test@example.com",
            Password = "WrongPassword!"
        };

        var user = new ApplicationUser
        {
            Email = model.Email,
            IsActive = true
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(model.Email))
            .ReturnsAsync(user);

        _mockSignInManager.Setup(m => m.PasswordSignInAsync(user, model.Password, model.RememberMe, true))
            .ReturnsAsync(SignInResult.Failed);

        // Act
        var result = await _controller.Login(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
        Assert.False(_controller.ModelState.IsValid);
        Assert.Contains(_controller.ModelState.Values,
            v => v.Errors.Any(e => e.ErrorMessage == "Invalid login attempt."));
    }

    #endregion

    #region Register GET Tests

    [Fact]
    public void Register_Get_ReturnsViewResult_WithViewModel()
    {
        // Arrange
        var returnUrl = "/connect/authorize";

        // Act
        var result = _controller.Register(returnUrl);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<RegisterViewModel>(viewResult.Model);
        Assert.Equal(returnUrl, model.ReturnUrl);
    }

    #endregion

    #region Register POST Tests

    [Fact]
    public async Task Register_Post_InvalidModelState_ReturnsViewWithModel()
    {
        // Arrange
        var model = new RegisterViewModel { Email = "test@example.com" };
        _controller.ModelState.AddModelError("Password", "Required");

        // Act
        var result = await _controller.Register(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
    }

    [Fact]
    public async Task Register_Post_SuccessfulRegistration_SignsInAndRedirects()
    {
        // Arrange
        var model = new RegisterViewModel
        {
            Email = "newuser@example.com",
            Password = "Password123!",
            ConfirmPassword = "Password123!",
            FullName = "New User"
        };

        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), model.Password))
            .ReturnsAsync(IdentityResult.Success);

        _mockSignInManager.Setup(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, null))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Register(model);

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirectResult.ActionName);
        Assert.Equal("Home", redirectResult.ControllerName);

        _mockUserManager.Verify(m => m.CreateAsync(
            It.Is<ApplicationUser>(u =>
                u.Email == model.Email &&
                u.UserName == model.Email &&
                u.FullName == model.FullName &&
                u.IsActive),
            model.Password),
            Times.Once);

        _mockSignInManager.Verify(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, null), Times.Once);
    }

    [Fact]
    public async Task Register_Post_SuccessfulRegistrationWithReturnUrl_RedirectsToReturnUrl()
    {
        // Arrange
        var returnUrl = "/connect/authorize";
        var model = new RegisterViewModel
        {
            Email = "newuser@example.com",
            Password = "Password123!",
            ConfirmPassword = "Password123!",
            ReturnUrl = returnUrl
        };

        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), model.Password))
            .ReturnsAsync(IdentityResult.Success);

        _mockSignInManager.Setup(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, null))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Register(model);

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Equal(returnUrl, redirectResult.Url);
    }

    [Fact]
    public async Task Register_Post_FailedRegistration_AddsErrorsAndReturnsView()
    {
        // Arrange
        var model = new RegisterViewModel
        {
            Email = "invalid@example.com",
            Password = "weak"
        };

        var errors = new[]
        {
            new IdentityError { Description = "Password too weak" },
            new IdentityError { Description = "Email already exists" }
        };

        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), model.Password))
            .ReturnsAsync(IdentityResult.Failed(errors));

        // Act
        var result = await _controller.Register(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Same(model, viewResult.Model);
        Assert.False(_controller.ModelState.IsValid);
        Assert.Equal(2, _controller.ModelState.ErrorCount);
    }

    #endregion

    #region Logout Tests

    [Fact]
    public async Task Logout_SignsOutAndRedirects()
    {
        // Arrange
        _mockSignInManager.Setup(m => m.SignOutAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Logout();

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirectResult.ActionName);
        Assert.Equal("Home", redirectResult.ControllerName);

        _mockSignInManager.Verify(m => m.SignOutAsync(), Times.Once);
    }

    #endregion

    #region AccessDenied Tests

    [Fact]
    public void AccessDenied_ReturnsViewResult()
    {
        // Act
        var result = _controller.AccessDenied();

        // Assert
        Assert.IsType<ViewResult>(result);
    }

    #endregion

    #region ChangePassword Tests

    [Fact]
    public async Task ChangePassword_Get_ReturnsViewWithReturnUrl()
    {
        // Arrange
        var returnUrl = "/some-return-url";

        // Act
        var result = _controller.ChangePassword(returnUrl);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal(returnUrl, viewResult.ViewData["ReturnUrl"]);
    }

    [Fact]
    public async Task ChangePassword_Post_SamePassword_ReturnsError()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "test-user-id",
            Email = "test@example.com",
            UserName = "test@example.com",
            MustChangePassword = true
        };

        var model = new ChangePasswordViewModel
        {
            NewPassword = "CurrentPass123!",
            ConfirmPassword = "CurrentPass123!"
        };

        // Setup mocks
        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>()))
            .ReturnsAsync(user);

        // Simulate password check returning true (same password)
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.NewPassword))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ChangePassword(model);

        // Assert
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.False(_controller.ModelState.IsValid);
        Assert.Contains(_controller.ModelState.Values.SelectMany(v => v.Errors),
            e => e.ErrorMessage.Contains("same as your current password"));
    }

    [Fact]
    public async Task ChangePassword_Post_DifferentPassword_Succeeds()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "test-user-id",
            Email = "test@example.com",
            UserName = "test@example.com",
            MustChangePassword = true
        };

        var model = new ChangePasswordViewModel
        {
            NewPassword = "NewPass456!",
            ConfirmPassword = "NewPass456!",
            ReturnUrl = "/"
        };

        // Setup mocks
        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>()))
            .ReturnsAsync(user);

        // Simulate password check returning false (different password)
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.NewPassword))
            .ReturnsAsync(false);

        _mockUserManager.Setup(m => m.GeneratePasswordResetTokenAsync(user))
            .ReturnsAsync("reset-token");

        _mockUserManager.Setup(m => m.ResetPasswordAsync(user, "reset-token", model.NewPassword))
            .ReturnsAsync(IdentityResult.Success);

        _mockUserManager.Setup(m => m.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        _mockUserManager.Setup(m => m.UpdateSecurityStampAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        _mockAuditService.Setup(a => a.LogAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.ChangePassword(model);

        // Assert - Could be LocalRedirectResult or RedirectResult depending on URL validation
        if (result is LocalRedirectResult localRedirect)
        {
            Assert.Equal("/", localRedirect.Url);
        }
        else
        {
            var redirectResult = Assert.IsType<RedirectResult>(result);
            Assert.Equal("/", redirectResult.Url);
        }
        Assert.False(user.MustChangePassword);
    }

    [Fact]
    public async Task ChangePassword_Post_NotLoggedIn_RedirectsToLogin()
    {
        // Arrange
        var model = new ChangePasswordViewModel
        {
            NewPassword = "NewPass456!",
            ConfirmPassword = "NewPass456!"
        };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.ChangePassword(model);

        // Assert
        var redirectResult = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Login", redirectResult.ActionName);
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

    private static SessionService CreateSessionService()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        var dbContext = new ApplicationDbContext(options);
        var logger = new Mock<ILogger<SessionService>>();
        var configuration = new Mock<IConfiguration>();

        return new SessionService(
            dbContext,
            logger.Object,
            configuration.Object);
    }

    #endregion
}
