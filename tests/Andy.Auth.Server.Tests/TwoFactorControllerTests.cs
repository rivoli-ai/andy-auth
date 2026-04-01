using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Andy.Auth.Server.Tests;

public class TwoFactorControllerTests
{
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<SignInManager<ApplicationUser>> _signInManagerMock;
    private readonly Mock<ILogger<TwoFactorController>> _loggerMock;
    private readonly TwoFactorController _controller;
    private readonly ApplicationUser _testUser;

    public TwoFactorControllerTests()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
        _signInManagerMock = new Mock<SignInManager<ApplicationUser>>(
            _userManagerMock.Object, contextAccessor.Object, claimsFactory.Object, null!, null!, null!, null!);

        _loggerMock = new Mock<ILogger<TwoFactorController>>();

        _controller = new TwoFactorController(
            _userManagerMock.Object,
            _signInManagerMock.Object,
            _loggerMock.Object,
            UrlEncoder.Default);

        _testUser = new ApplicationUser
        {
            Id = "test-user-id",
            UserName = "test@example.com",
            Email = "test@example.com"
        };

        SetupHttpContext();
    }

    private void SetupHttpContext()
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, _testUser.Id),
            new(ClaimTypes.Email, _testUser.Email!)
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext { User = principal };
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());

        _userManagerMock.Setup(x => x.GetUserAsync(principal)).ReturnsAsync(_testUser);
    }

    // ==================== Index Tests ====================

    [Fact]
    public async Task Index_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.Index();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task Index_UserWith2faEnabled_ReturnsViewWithCorrectModel()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync("TESTKEY123456789");
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser))
            .ReturnsAsync(true);
        _userManagerMock.Setup(x => x.CountRecoveryCodesAsync(_testUser))
            .ReturnsAsync(5);

        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<TwoFactorIndexViewModel>().Subject;
        model.HasAuthenticator.Should().BeTrue();
        model.Is2faEnabled.Should().BeTrue();
        model.RecoveryCodesLeft.Should().Be(5);
    }

    [Fact]
    public async Task Index_UserWithout2fa_ReturnsViewWithCorrectModel()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync((string?)null);
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser))
            .ReturnsAsync(false);
        _userManagerMock.Setup(x => x.CountRecoveryCodesAsync(_testUser))
            .ReturnsAsync(0);

        // Act
        var result = await _controller.Index();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<TwoFactorIndexViewModel>().Subject;
        model.HasAuthenticator.Should().BeFalse();
        model.Is2faEnabled.Should().BeFalse();
        model.RecoveryCodesLeft.Should().Be(0);
    }

    // ==================== EnableAuthenticator GET Tests ====================

    [Fact]
    public async Task EnableAuthenticator_Get_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.EnableAuthenticator();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task EnableAuthenticator_Get_ExistingKey_ReturnsViewWithKeyAndQrCode()
    {
        // Arrange
        var authenticatorKey = "JBSWY3DPEHPK3PXP";
        _userManagerMock.Setup(x => x.GetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(authenticatorKey);
        _userManagerMock.Setup(x => x.GetEmailAsync(_testUser))
            .ReturnsAsync(_testUser.Email);

        // Act
        var result = await _controller.EnableAuthenticator();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<EnableAuthenticatorViewModel>().Subject;
        model.SharedKey.Should().NotBeNullOrEmpty();
        model.AuthenticatorUri.Should().Contain("otpauth://totp/");
        model.QrCodeBase64.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task EnableAuthenticator_Get_NoExistingKey_GeneratesNewKey()
    {
        // Arrange
        var newKey = "NEWGENERATEDKEY123";
        _userManagerMock.SetupSequence(x => x.GetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync((string?)null)
            .ReturnsAsync(newKey);
        _userManagerMock.Setup(x => x.ResetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetEmailAsync(_testUser))
            .ReturnsAsync(_testUser.Email);

        // Act
        var result = await _controller.EnableAuthenticator();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<EnableAuthenticatorViewModel>().Subject;
        model.SharedKey.Should().NotBeNullOrEmpty();
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(_testUser), Times.Once);
    }

    // ==================== EnableAuthenticator POST Tests ====================

    [Fact]
    public async Task EnableAuthenticator_Post_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        var model = new EnableAuthenticatorViewModel { Code = "123456" };

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task EnableAuthenticator_Post_InvalidModelState_ReturnsViewWithModel()
    {
        // Arrange
        var authenticatorKey = "TESTKEY123456789";
        _userManagerMock.Setup(x => x.GetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(authenticatorKey);
        _userManagerMock.Setup(x => x.GetEmailAsync(_testUser))
            .ReturnsAsync(_testUser.Email);

        _controller.ModelState.AddModelError("Code", "Code is required");

        var model = new EnableAuthenticatorViewModel { Code = "" };

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        viewResult.Model.Should().BeOfType<EnableAuthenticatorViewModel>();
    }

    [Fact]
    public async Task EnableAuthenticator_Post_InvalidCode_ReturnsViewWithError()
    {
        // Arrange
        var authenticatorKey = "TESTKEY123456789";
        _userManagerMock.Setup(x => x.GetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(authenticatorKey);
        _userManagerMock.Setup(x => x.GetEmailAsync(_testUser))
            .ReturnsAsync(_testUser.Email);
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(
            _testUser,
            It.IsAny<string>(),
            "123456"))
            .ReturnsAsync(false);

        var model = new EnableAuthenticatorViewModel { Code = "123456" };

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        _controller.ModelState["Code"]!.Errors.Should().ContainSingle()
            .Which.ErrorMessage.Should().Be("Verification code is invalid.");
    }

    [Fact]
    public async Task EnableAuthenticator_Post_ValidCode_Enables2faAndRedirects()
    {
        // Arrange
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(
            _testUser,
            It.IsAny<string>(),
            "123456"))
            .ReturnsAsync(true);
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, true))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.CountRecoveryCodesAsync(_testUser))
            .ReturnsAsync(0);

        var model = new EnableAuthenticatorViewModel { Code = "123456" };

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("ShowRecoveryCodes");
        _userManagerMock.Verify(x => x.SetTwoFactorEnabledAsync(_testUser, true), Times.Once);
    }

    [Fact]
    public async Task EnableAuthenticator_Post_ValidCodeWithExistingRecoveryCodes_RedirectsToIndex()
    {
        // Arrange
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(
            _testUser,
            It.IsAny<string>(),
            "123456"))
            .ReturnsAsync(true);
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, true))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.CountRecoveryCodesAsync(_testUser))
            .ReturnsAsync(5);

        var model = new EnableAuthenticatorViewModel { Code = "123456" };

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
    }

    [Fact]
    public async Task EnableAuthenticator_Post_CodeWithSpacesAndHyphens_StripsFormatting()
    {
        // Arrange
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(
            _testUser,
            It.IsAny<string>(),
            "123456"))
            .ReturnsAsync(true);
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, true))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.CountRecoveryCodesAsync(_testUser))
            .ReturnsAsync(10);

        var model = new EnableAuthenticatorViewModel { Code = "123 456" }; // With space

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert
        result.Should().BeOfType<RedirectToActionResult>();
        _userManagerMock.Verify(x => x.VerifyTwoFactorTokenAsync(
            _testUser,
            It.IsAny<string>(),
            "123456"), Times.Once);
    }

    // ==================== ShowRecoveryCodes Tests ====================

    [Fact]
    public async Task ShowRecoveryCodes_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.ShowRecoveryCodes();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task ShowRecoveryCodes_GeneratesAndReturnsRecoveryCodes()
    {
        // Arrange
        var recoveryCodes = new[] { "CODE1", "CODE2", "CODE3", "CODE4", "CODE5",
            "CODE6", "CODE7", "CODE8", "CODE9", "CODE10" };
        _userManagerMock.Setup(x => x.GenerateNewTwoFactorRecoveryCodesAsync(_testUser, 10))
            .ReturnsAsync(recoveryCodes);

        // Act
        var result = await _controller.ShowRecoveryCodes();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<ShowRecoveryCodesViewModel>().Subject;
        model.RecoveryCodes.Should().HaveCount(10);
        model.RecoveryCodes.Should().BeEquivalentTo(recoveryCodes);
    }

    [Fact]
    public async Task ShowRecoveryCodes_NullRecoveryCodes_ReturnsEmptyArray()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GenerateNewTwoFactorRecoveryCodesAsync(_testUser, 10))
            .ReturnsAsync((IEnumerable<string>?)null);

        // Act
        var result = await _controller.ShowRecoveryCodes();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<ShowRecoveryCodesViewModel>().Subject;
        model.RecoveryCodes.Should().BeEmpty();
    }

    // ==================== GenerateRecoveryCodes Tests ====================

    [Fact]
    public async Task GenerateRecoveryCodes_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.GenerateRecoveryCodes();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task GenerateRecoveryCodes_2faNotEnabled_RedirectsWithError()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.GenerateRecoveryCodes();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
    }

    [Fact]
    public async Task GenerateRecoveryCodes_2faEnabled_RedirectsToShowRecoveryCodes()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.GenerateRecoveryCodes();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("ShowRecoveryCodes");
    }

    // ==================== Disable2fa GET Tests ====================

    [Fact]
    public async Task Disable2fa_Get_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.Disable2fa();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task Disable2fa_Get_2faNotEnabled_RedirectsToIndex()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.Disable2fa();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
    }

    [Fact]
    public async Task Disable2fa_Get_2faEnabled_ReturnsView()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.Disable2fa();

        // Assert
        result.Should().BeOfType<ViewResult>();
    }

    // ==================== Disable2faConfirmed Tests ====================

    [Fact]
    public async Task Disable2faConfirmed_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.Disable2faConfirmed();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task Disable2faConfirmed_DisableFails_RedirectsWithError()
    {
        // Arrange
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, false))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Error" }));

        // Act
        var result = await _controller.Disable2faConfirmed();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        _controller.TempData["ErrorMessage"].Should().NotBeNull();
    }

    [Fact]
    public async Task Disable2faConfirmed_Success_Disables2faAndResetsKey()
    {
        // Arrange
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, false))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.ResetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.Disable2faConfirmed();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("Index");
        _controller.TempData["StatusMessage"].Should().NotBeNull();
        _userManagerMock.Verify(x => x.SetTwoFactorEnabledAsync(_testUser, false), Times.Once);
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(_testUser), Times.Once);
    }

    // ==================== ResetAuthenticator Tests ====================

    [Fact]
    public async Task ResetAuthenticator_UserNotFound_ReturnsNotFound()
    {
        // Arrange
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _controller.ResetAuthenticator();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task ResetAuthenticator_Disables2faAndResetsKey()
    {
        // Arrange
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, false))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.ResetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.ResetAuthenticator();

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("EnableAuthenticator");
        _controller.TempData["StatusMessage"].Should().NotBeNull();
        _userManagerMock.Verify(x => x.SetTwoFactorEnabledAsync(_testUser, false), Times.Once);
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(_testUser), Times.Once);
    }
}
