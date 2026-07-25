using System.Security.Claims;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    private Mock<IAuthenticationService> _mockAuthService = new();

    public AccountControllerTests()
    {
        _mockUserManager = MockUserManager();
        _mockSignInManager = MockSignInManager(_mockUserManager.Object);
        _mockAuditService = new Mock<IAuditService>();
        _sessionService = CreateSessionService();
        _mockLogger = new Mock<ILogger<AccountController>>();

        _controller = BuildController(new ExternalLoginOptions());
    }

    /// <summary>
    /// Builds the controller under test with the supplied external-login policy,
    /// wiring up the URL helper and an empty (unauthenticated) HTTP context.
    /// </summary>
    private AccountController BuildController(ExternalLoginOptions externalLoginOptions)
    {
        var controller = new AccountController(
            _mockSignInManager.Object,
            _mockUserManager.Object,
            _mockAuditService.Object,
            _sessionService,
            Options.Create(externalLoginOptions),
            _mockLogger.Object);

        // Setup controller context for URL helper
        var httpContext = new DefaultHttpContext();

        // HttpContext.SignOutAsync(IdentityConstants.ExternalScheme) resolves
        // IAuthenticationService from RequestServices; wire a mock so the
        // external-scheme sign-out on rejection paths works under unit test.
        _mockAuthService = new Mock<IAuthenticationService>();
        _mockAuthService
            .Setup(a => a.SignOutAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);
        var services = new ServiceCollection();
        services.AddSingleton(_mockAuthService.Object);
        httpContext.RequestServices = services.BuildServiceProvider();

        var mockUrlHelper = new Mock<IUrlHelper>();
        mockUrlHelper
            .Setup(x => x.IsLocalUrl(It.IsAny<string>()))
            .Returns((string url) => !string.IsNullOrEmpty(url) && url.StartsWith('/'));

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
        controller.Url = mockUrlHelper.Object;
        controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());
        return controller;
    }

    /// <summary>
    /// Marks the controller's HTTP context as an authenticated session for the
    /// given user id (used by the account-linking tests).
    /// </summary>
    private static void SignInSession(AccountController controller, string userId)
    {
        var identity = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.NameIdentifier, userId) },
            authenticationType: "TestAuth");
        controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Builds an <see cref="ExternalLoginInfo"/> for a provider callback with the
    /// supplied email and optional extra claims (e.g. email_verified, tid, iss).
    /// </summary>
    private static ExternalLoginInfo BuildExternalLoginInfo(
        string? email,
        string provider = "Microsoft",
        string providerKey = "external-key-123",
        params Claim[] extraClaims)
    {
        var claims = new List<Claim>();
        if (!string.IsNullOrEmpty(email))
        {
            claims.Add(new Claim(ClaimTypes.Email, email));
            claims.Add(new Claim(ClaimTypes.Name, email));
        }
        claims.AddRange(extraClaims);

        var identity = new ClaimsIdentity(claims, authenticationType: provider);
        var principal = new ClaimsPrincipal(identity);
        return new ExternalLoginInfo(principal, provider, providerKey, provider);
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
            v => v.Errors.Any(e => e.ErrorMessage == "Invalid login attempt. If the problem persists, contact your administrator."));
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
            // andy-auth#50: without the correct password, a disabled account must
            // be indistinguishable from a wrong one.
            v => v.Errors.Any(e => e.ErrorMessage == "Invalid login attempt. If the problem persists, contact your administrator."));
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
            // Lockout goes to the log and audit trail; the form only says it to a
            // caller who supplied the right password.
            v => v.Errors.Any(e => e.ErrorMessage == "Invalid login attempt. If the problem persists, contact your administrator."));
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
            v => v.Errors.Any(e => e.ErrorMessage == "Invalid login attempt. If the problem persists, contact your administrator."));
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
            CurrentPassword = "CurrentPass123!",
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
            CurrentPassword = "CurrentPass123!",
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

        // Post-#45: ChangePasswordAsync replaces the GeneratePasswordResetToken
        // + ResetPassword pair and verifies the current password atomically.
        _mockUserManager.Setup(m => m.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword))
            .ReturnsAsync(IdentityResult.Success);

        _mockUserManager.Setup(m => m.GetTwoFactorEnabledAsync(user))
            .ReturnsAsync(false);

        _mockUserManager.Setup(m => m.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        _mockSignInManager.Setup(m => m.RefreshSignInAsync(user))
            .Returns(Task.CompletedTask);

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
            CurrentPassword = "CurrentPass123!",
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

    [Fact]
    public async Task ChangePassword_Post_MissingCurrentPassword_FailsModelValidation()
    {
        // Regression for andy-auth#45. Pre-fix the view model had no
        // CurrentPassword field at all and the controller called
        // ResetPasswordAsync, so a stolen-cookie attacker could change the
        // password without proving knowledge of the old one. The
        // [Required] attribute on CurrentPassword is the contract that
        // must hold. Validate via the framework's metadata-aware
        // validator so we test the same path MVC executes per request.
        var model = new ChangePasswordViewModel
        {
            CurrentPassword = string.Empty,
            NewPassword = "NewPass456!",
            ConfirmPassword = "NewPass456!"
        };

        var validationContext = new System.ComponentModel.DataAnnotations.ValidationContext(model);
        var validationResults = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
        var isValid = System.ComponentModel.DataAnnotations.Validator.TryValidateObject(
            model, validationContext, validationResults, validateAllProperties: true);

        Assert.False(isValid, "ChangePasswordViewModel must reject empty CurrentPassword");
        Assert.Contains(validationResults, r =>
            r.MemberNames.Contains(nameof(ChangePasswordViewModel.CurrentPassword)));
    }

    [Fact]
    public async Task ChangePassword_Post_WrongCurrentPassword_RejectsWithoutChangingPassword()
    {
        // Regression for andy-auth#45. Identity surfaces a "PasswordMismatch"
        // error when the supplied current password is wrong; the controller
        // must surface it and not call ResetPasswordAsync (which would have
        // bypassed the check entirely under the old code path).
        var user = new ApplicationUser
        {
            Id = "test-user-id",
            Email = "test@example.com",
            UserName = "test@example.com",
        };

        var model = new ChangePasswordViewModel
        {
            CurrentPassword = "WrongPassword!",
            NewPassword = "NewPass456!",
            ConfirmPassword = "NewPass456!"
        };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>()))
            .ReturnsAsync(user);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.NewPassword))
            .ReturnsAsync(false);
        _mockUserManager.Setup(m => m.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError
            {
                Code = "PasswordMismatch",
                Description = "Incorrect password."
            }));

        var result = await _controller.ChangePassword(model);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.False(_controller.ModelState.IsValid);
        // The reset-token APIs must NOT have been called: that's the buggy
        // pre-fix code path the regression test guards.
        _mockUserManager.Verify(m => m.GeneratePasswordResetTokenAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _mockUserManager.Verify(m => m.ResetPasswordAsync(
            It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        // Sign-in must not have been refreshed since the change failed.
        _mockSignInManager.Verify(m => m.RefreshSignInAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    #endregion

    #region External Login (andy-auth#119) Tests

    private static Claim VerifiedEmail() => new("email_verified", "true");

    [Fact]
    public async Task ExternalLoginCallback_RemoteError_ReturnsLoginView()
    {
        var result = await _controller.ExternalLoginCallback(returnUrl: "/", remoteError: "access_denied");

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
    }

    [Fact]
    public async Task ExternalLoginCallback_AlreadyLinkedActiveUser_SignsInWithoutBypassingTwoFactor()
    {
        var user = new ApplicationUser { Id = "u1", Email = "linked@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("linked@example.com", providerKey: "pk-linked", extraClaims: VerifiedEmail());

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey)).ReturnsAsync(user);
        // The linked path must NOT bypass local 2FA.
        _mockSignInManager
            .Setup(m => m.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false, false))
            .ReturnsAsync(SignInResult.Success);
        _mockUserManager.Setup(m => m.UpdateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        _mockSignInManager.Verify(
            m => m.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false, false), Times.Once);
        // Bypass variant must never be used.
        _mockSignInManager.Verify(
            m => m.ExternalLoginSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), true), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("UserLoginExternal",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_AlreadyLinkedUser_RequiresTwoFactor_RedirectsToLoginWith2fa()
    {
        var user = new ApplicationUser { Id = "u1", Email = "linked@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("linked@example.com", providerKey: "pk-2fa", extraClaims: VerifiedEmail());

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey)).ReturnsAsync(user);
        _mockSignInManager
            .Setup(m => m.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false, false))
            .ReturnsAsync(SignInResult.TwoFactorRequired);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(AccountController.LoginWith2fa), redirect.ActionName);
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("deleted")]
    [InlineData("expired")]
    [InlineData("inactive")]
    public async Task ExternalLoginCallback_AlreadyLinkedButBlockedUser_RejectsWithoutSignIn(string state)
    {
        var user = new ApplicationUser { Id = "u1", Email = "blocked@example.com", IsActive = true };
        switch (state)
        {
            case "suspended": user.IsSuspended = true; break;
            case "deleted": user.DeletedAt = DateTime.UtcNow; break;
            case "expired": user.ExpiresAt = DateTime.UtcNow.AddDays(-1); break;
            case "inactive": user.IsActive = false; break;
        }

        var info = BuildExternalLoginInfo("blocked@example.com", providerKey: "pk-blocked", extraClaims: VerifiedEmail());
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey)).ReturnsAsync(user);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        // Blocked users must never reach the sign-in call.
        _mockSignInManager.Verify(
            m => m.ExternalLoginSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()),
            Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("UserLoginExternalRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_NoExistingAccount_ProvisionsNewUserAndSignsIn()
    {
        var info = BuildExternalLoginInfo("brand-new@example.com", providerKey: "pk-new", extraClaims: VerifiedEmail());
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("brand-new@example.com"))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), info)).ReturnsAsync(IdentityResult.Success);
        _mockSignInManager.Setup(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, null)).Returns(Task.CompletedTask);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        Assert.IsType<RedirectToActionResult>(result);
        _mockUserManager.Verify(m => m.CreateAsync(It.Is<ApplicationUser>(u => u.Email == "brand-new@example.com")), Times.Once);
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), info), Times.Once);
        _mockAuditService.Verify(a => a.LogAsync("UserRegisteredExternal",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_ExistingEmail_NoAuthenticatedSession_RefusesToLink()
    {
        // THE core bug (#119): an unauthenticated provider callback whose email
        // matches an existing account must NOT be auto-linked or signed in.
        var existing = new ApplicationUser { Id = "victim", Email = "victim@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("victim@example.com", providerKey: "pk-attacker", extraClaims: VerifiedEmail());

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("victim@example.com")).ReturnsAsync(existing);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        // No link created, nobody signed in.
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<ExternalLoginInfo>()), Times.Never);
        _mockSignInManager.Verify(m => m.SignInAsync(It.IsAny<ApplicationUser>(), It.IsAny<bool>(), It.IsAny<string>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_ExistingEmail_AuthenticatedSameUser_RedirectsToLinkConfirmation()
    {
        var existing = new ApplicationUser { Id = "owner", Email = "owner@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("owner@example.com", providerKey: "pk-owner", extraClaims: VerifiedEmail());

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("owner@example.com")).ReturnsAsync(existing);
        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(existing);

        SignInSession(_controller, "owner");

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(AccountController.LinkExternalLogin), redirect.ActionName);
        // Still must not have auto-linked; the ownership challenge happens in the confirm step.
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<ExternalLoginInfo>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRequested",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_UnverifiedEmail_Rejected()
    {
        var info = BuildExternalLoginInfo("unverified@example.com", providerKey: "pk-unverified"); // no email_verified claim
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        // Rejected before any account lookup / creation.
        _mockUserManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        _mockUserManager.Verify(m => m.CreateAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_UnverifiedEmailAllowed_WhenPolicyDisablesRequirement()
    {
        var controller = BuildController(new ExternalLoginOptions { RequireVerifiedEmail = false });
        var info = BuildExternalLoginInfo("noverify@example.com", providerKey: "pk-noverify"); // no email_verified claim
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("noverify@example.com")).ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), info)).ReturnsAsync(IdentityResult.Success);
        _mockSignInManager.Setup(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, null)).Returns(Task.CompletedTask);

        var result = await controller.ExternalLoginCallback(returnUrl: null);

        Assert.IsType<RedirectToActionResult>(result);
        _mockUserManager.Verify(m => m.CreateAsync(It.IsAny<ApplicationUser>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_TenantNotAllowed_Rejected()
    {
        var controller = BuildController(new ExternalLoginOptions
        {
            AllowedTenantIds = new List<string> { "allowed-tenant" }
        });
        var info = BuildExternalLoginInfo("user@other.com", providerKey: "pk-tenant",
            extraClaims: new[] { VerifiedEmail(), new Claim("tid", "some-other-tenant") });

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await controller.ExternalLoginCallback(returnUrl: null);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        _mockUserManager.Verify(m => m.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_TenantAllowed_ProceedsToProvisioning()
    {
        var controller = BuildController(new ExternalLoginOptions
        {
            AllowedTenantIds = new List<string> { "allowed-tenant" }
        });
        var info = BuildExternalLoginInfo("user@allowed.com", providerKey: "pk-tenant-ok",
            extraClaims: new[] { VerifiedEmail(), new Claim("tid", "allowed-tenant") });

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("user@allowed.com")).ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), info)).ReturnsAsync(IdentityResult.Success);
        _mockSignInManager.Setup(m => m.SignInAsync(It.IsAny<ApplicationUser>(), false, null)).Returns(Task.CompletedTask);

        var result = await controller.ExternalLoginCallback(returnUrl: null);

        Assert.IsType<RedirectToActionResult>(result);
        _mockUserManager.Verify(m => m.CreateAsync(It.IsAny<ApplicationUser>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_NoEmailClaim_Rejected()
    {
        var info = BuildExternalLoginInfo(email: null, providerKey: "pk-noemail");
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
    }

    [Fact]
    public async Task LinkExternalLogin_Post_CorrectPassword_LinksAndAuditsSuccess()
    {
        var user = new ApplicationUser { Id = "owner", Email = "owner@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("owner@example.com", providerKey: "pk-confirm", extraClaims: VerifiedEmail());
        var model = new LinkExternalLoginViewModel { Password = "CorrectPass123!", Provider = "Microsoft" };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.Password)).ReturnsAsync(true);
        _mockUserManager.Setup(m => m.AddLoginAsync(user, info)).ReturnsAsync(IdentityResult.Success);
        _mockSignInManager.Setup(m => m.RefreshSignInAsync(user)).Returns(Task.CompletedTask);

        SignInSession(_controller, "owner");

        var result = await _controller.LinkExternalLogin(model);

        Assert.IsType<RedirectToActionResult>(result);
        _mockUserManager.Verify(m => m.AddLoginAsync(user, info), Times.Once);
        _mockSignInManager.Verify(m => m.RefreshSignInAsync(user), Times.Once);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkSucceeded",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task LinkExternalLogin_Post_WrongPassword_RejectsWithoutLinking()
    {
        var user = new ApplicationUser { Id = "owner", Email = "owner@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("owner@example.com", providerKey: "pk-confirm2", extraClaims: VerifiedEmail());
        var model = new LinkExternalLoginViewModel { Password = "WrongPass!", Provider = "Microsoft" };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.Password)).ReturnsAsync(false);

        SignInSession(_controller, "owner");

        var result = await _controller.LinkExternalLogin(model);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.False(_controller.ModelState.IsValid);
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<ExternalLoginInfo>()), Times.Never);
        _mockSignInManager.Verify(m => m.RefreshSignInAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_ExistingEmail_NoSession_SignsOutExternalScheme()
    {
        // A rejected ExternalLoginInfo must not remain replayable into the link
        // flow: the external scheme cookie is dropped on rejection.
        var existing = new ApplicationUser { Id = "victim", Email = "victim@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("victim@example.com", providerKey: "pk-signout", extraClaims: VerifiedEmail());

        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("victim@example.com")).ReturnsAsync(existing);

        await _controller.ExternalLoginCallback(returnUrl: null);

        _mockAuthService.Verify(a => a.SignOutAsync(
            It.IsAny<HttpContext>(), IdentityConstants.ExternalScheme, It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_UnverifiedEmail_SignsOutExternalScheme()
    {
        var info = BuildExternalLoginInfo("unverified@example.com", providerKey: "pk-unverified-signout");
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);

        await _controller.ExternalLoginCallback(returnUrl: null);

        _mockAuthService.Verify(a => a.SignOutAsync(
            It.IsAny<HttpContext>(), IdentityConstants.ExternalScheme, It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task ExternalLoginCallback_NoExistingAccount_AddLoginFails_RollsBackAndDoesNotSignIn()
    {
        var info = BuildExternalLoginInfo("orphan@example.com", providerKey: "pk-orphan", extraClaims: VerifiedEmail());
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
            .ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.FindByEmailAsync("orphan@example.com")).ReturnsAsync((ApplicationUser?)null);
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), info))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "login exists" }));
        _mockUserManager.Setup(m => m.DeleteAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);

        var result = await _controller.ExternalLoginCallback(returnUrl: null);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Login", viewResult.ViewName);
        // The orphaned passwordless account must be rolled back and nobody signed in.
        _mockUserManager.Verify(m => m.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Once);
        _mockSignInManager.Verify(m => m.SignInAsync(It.IsAny<ApplicationUser>(), It.IsAny<bool>(), It.IsAny<string>()), Times.Never);
        _mockAuthService.Verify(a => a.SignOutAsync(
            It.IsAny<HttpContext>(), IdentityConstants.ExternalScheme, It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task LinkExternalLogin_Post_UnverifiedEmail_RejectsWithoutLinking()
    {
        // Replay-into-link defense: even with a valid session, matching email and
        // correct password, an unverified external email must not be linked.
        var user = new ApplicationUser { Id = "owner", Email = "owner@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("owner@example.com", providerKey: "pk-link-unverified"); // no email_verified
        var model = new LinkExternalLoginViewModel { Password = "CorrectPass123!", Provider = "Microsoft" };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.Password)).ReturnsAsync(true);

        SignInSession(_controller, "owner");

        var result = await _controller.LinkExternalLogin(model);

        Assert.IsType<ViewResult>(result);
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<ExternalLoginInfo>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task LinkExternalLogin_Post_DisallowedTenant_RejectsWithoutLinking()
    {
        var controller = BuildController(new ExternalLoginOptions
        {
            AllowedTenantIds = new List<string> { "allowed-tenant" }
        });
        var user = new ApplicationUser { Id = "owner", Email = "owner@example.com", IsActive = true };
        var info = BuildExternalLoginInfo("owner@example.com", providerKey: "pk-link-tenant",
            extraClaims: new[] { VerifiedEmail(), new Claim("tid", "some-other-tenant") });
        var model = new LinkExternalLoginViewModel { Password = "CorrectPass123!", Provider = "Microsoft" };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.Password)).ReturnsAsync(true);

        SignInSession(controller, "owner");

        var result = await controller.LinkExternalLogin(model);

        Assert.IsType<ViewResult>(result);
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<ExternalLoginInfo>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task LinkExternalLogin_Post_ProviderEmailMismatch_Rejected()
    {
        var user = new ApplicationUser { Id = "owner", Email = "owner@example.com", IsActive = true };
        // External identity carries a DIFFERENT email than the signed-in account.
        var info = BuildExternalLoginInfo("someone-else@example.com", providerKey: "pk-mismatch", extraClaims: VerifiedEmail());
        var model = new LinkExternalLoginViewModel { Password = "CorrectPass123!", Provider = "Microsoft" };

        _mockUserManager.Setup(m => m.GetUserAsync(It.IsAny<ClaimsPrincipal>())).ReturnsAsync(user);
        _mockSignInManager.Setup(m => m.GetExternalLoginInfoAsync(null)).ReturnsAsync(info);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(user, model.Password)).ReturnsAsync(true);

        SignInSession(_controller, "owner");

        var result = await _controller.LinkExternalLogin(model);

        Assert.IsType<ViewResult>(result);
        _mockUserManager.Verify(m => m.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<ExternalLoginInfo>()), Times.Never);
        _mockAuditService.Verify(a => a.LogAsync("ExternalLinkRejected",
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>()), Times.Once);
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

    // ==================== andy-auth#50: no enumeration oracle ====================

    [Fact]
    public async Task Login_Post_AllFailureModes_ReportTheSameMessage()
    {
        // The oracle wasn't one message — it was the *difference* between them.
        // "no such account", "disabled" and "wrong password" each identified
        // which emails are real. This is the invariant, so assert it directly
        // rather than three separate strings that can drift apart again.
        var messages = new List<string>();

        // (a) no such account
        _mockUserManager.Setup(m => m.FindByEmailAsync("ghost@example.com"))
            .ReturnsAsync((ApplicationUser?)null);
        await RunLoginAndCollect("ghost@example.com", messages);

        // (b) account exists but is suspended
        var suspended = new ApplicationUser
        {
            Id = "u2", Email = "suspended@example.com", IsActive = true, IsSuspended = true
        };
        _mockUserManager.Setup(m => m.FindByEmailAsync("suspended@example.com")).ReturnsAsync(suspended);
        await RunLoginAndCollect("suspended@example.com", messages);

        // (c) account exists, password wrong
        var healthy = new ApplicationUser { Id = "u3", Email = "real@example.com", IsActive = true };
        _mockUserManager.Setup(m => m.FindByEmailAsync("real@example.com")).ReturnsAsync(healthy);
        _mockSignInManager.Setup(m => m.PasswordSignInAsync(
                healthy, It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Failed);
        await RunLoginAndCollect("real@example.com", messages);

        // (d) account exists, locked out
        var locked = new ApplicationUser { Id = "u4", Email = "locked@example.com", IsActive = true };
        _mockUserManager.Setup(m => m.FindByEmailAsync("locked@example.com")).ReturnsAsync(locked);
        _mockSignInManager.Setup(m => m.PasswordSignInAsync(
                locked, It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);
        await RunLoginAndCollect("locked@example.com", messages);

        messages.Should().HaveCount(4);
        messages.Distinct().Should().ContainSingle(
            "without the correct password, every failure mode must look identical");
    }

    [Fact]
    public async Task Login_Post_LockedOut_WithCorrectPassword_ExplainsTheLockout()
    {
        // andy-auth#50: the disclosure is gated on knowing the password, not
        // removed. Someone who can already authenticate learns nothing new from
        // being told the account is locked — so they get a usable explanation
        // instead of a dead end.
        var locked = new ApplicationUser { Id = "u5", Email = "locked2@example.com", IsActive = true };
        _mockUserManager.Setup(m => m.FindByEmailAsync("locked2@example.com")).ReturnsAsync(locked);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(locked, "CorrectPassword123!")).ReturnsAsync(true);
        _mockSignInManager.Setup(m => m.PasswordSignInAsync(
                locked, It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);

        await _controller.Login(new LoginViewModel
        {
            Email = "locked2@example.com",
            Password = "CorrectPassword123!"
        });

        _controller.ModelState.Values
            .SelectMany(v => v.Errors)
            .Single().ErrorMessage
            .Should().Contain("temporarily locked");
    }

    [Fact]
    public async Task Login_Post_Disabled_WithCorrectPassword_ExplainsTheDisabledAccount()
    {
        var suspended = new ApplicationUser
        {
            Id = "u6", Email = "suspended2@example.com", IsActive = true, IsSuspended = true
        };
        _mockUserManager.Setup(m => m.FindByEmailAsync("suspended2@example.com")).ReturnsAsync(suspended);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(suspended, "CorrectPassword123!")).ReturnsAsync(true);

        await _controller.Login(new LoginViewModel
        {
            Email = "suspended2@example.com",
            Password = "CorrectPassword123!"
        });

        _controller.ModelState.Values
            .SelectMany(v => v.Errors)
            .Single().ErrorMessage
            .Should().Contain("not currently able to sign in");
    }

    [Fact]
    public async Task Login_Post_Disabled_WithWrongPassword_StaysGeneric()
    {
        // The other half of the invariant: an attacker probing a suspended
        // account without its password must not be able to tell it apart from
        // an address that was never registered.
        var suspended = new ApplicationUser
        {
            Id = "u7", Email = "suspended3@example.com", IsActive = true, IsSuspended = true
        };
        _mockUserManager.Setup(m => m.FindByEmailAsync("suspended3@example.com")).ReturnsAsync(suspended);
        _mockUserManager.Setup(m => m.CheckPasswordAsync(suspended, It.IsAny<string>())).ReturnsAsync(false);

        await _controller.Login(new LoginViewModel
        {
            Email = "suspended3@example.com",
            Password = "WrongPassword123!"
        });

        _controller.ModelState.Values
            .SelectMany(v => v.Errors)
            .Single().ErrorMessage
            .Should().Be("Invalid login attempt. If the problem persists, contact your administrator.");
    }

    private async Task RunLoginAndCollect(string email, List<string> messages)
    {
        _controller.ModelState.Clear();
        var result = await _controller.Login(new LoginViewModel
        {
            Email = email,
            Password = "WrongPassword123!"
        });

        Assert.IsType<ViewResult>(result);
        messages.Add(_controller.ModelState.Values
            .SelectMany(v => v.Errors)
            .Select(e => e.ErrorMessage)
            .Single());
    }
}
