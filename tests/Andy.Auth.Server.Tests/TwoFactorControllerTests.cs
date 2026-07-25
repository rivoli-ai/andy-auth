using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
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

        // VerifyStepUpAsync reads Options.Tokens.AuthenticatorTokenProvider.
        _userManagerMock.Object.Options = new IdentityOptions();

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
    public async Task EnableAuthenticator_Post_ValidCode_Enables2faAndShowsRecoveryCodes()
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

        _userManagerMock.Setup(x => x.GenerateNewTwoFactorRecoveryCodesAsync(_testUser, 10))
            .ReturnsAsync(new[] { "C1", "C2" });

        var model = new EnableAuthenticatorViewModel { Code = "123456" };

        // Act
        var result = await _controller.EnableAuthenticator(model);

        // Assert — rendered directly rather than redirecting to a GET that
        // generated codes as a side effect (andy-auth#52).
        var view = result.Should().BeOfType<ViewResult>().Subject;
        view.ViewName.Should().Be("ShowRecoveryCodes");
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

    // ==================== 2FA step-up (andy-auth#52) ====================

    private const string CorrectPassword = "CorrectHorse1!";
    private const string CorrectCode = "123456";

    /// <summary>Mocks a user with 2FA on and a step-up that will succeed.</summary>
    private void ArrangeValidStepUp(bool twoFactorEnabled = true)
    {
        _userManagerMock.Setup(x => x.GetTwoFactorEnabledAsync(_testUser)).ReturnsAsync(twoFactorEnabled);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(_testUser, CorrectPassword)).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(_testUser, It.Is<string>(p => p != CorrectPassword)))
            .ReturnsAsync(false);
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(_testUser, It.IsAny<string>(), CorrectCode))
            .ReturnsAsync(true);
        _userManagerMock.Setup(x => x.VerifyTwoFactorTokenAsync(
                _testUser, It.IsAny<string>(), It.Is<string>(c => c != CorrectCode)))
            .ReturnsAsync(false);
    }

    private static TwoFactorStepUpViewModel ValidStepUp() => new()
    {
        CurrentPassword = CorrectPassword,
        TwoFactorCode = CorrectCode,
    };

    [Fact]
    public void ShowRecoveryCodes_IsNoLongerAReachableAction()
    {
        // The GET generated a fresh set of codes as a side effect, so merely
        // loading the URL — an <img> on any page, a link prefetch — silently
        // voided the user's existing codes. Generation now lives only on the
        // antiforgery-protected POST.
        typeof(TwoFactorController).GetMethod("ShowRecoveryCodes").Should().BeNull();
    }

    [Fact]
    public async Task GenerateRecoveryCodes_Get_DoesNotGenerateAnything()
    {
        ArrangeValidStepUp();

        var result = await _controller.GenerateRecoveryCodes();

        result.Should().BeOfType<ViewResult>()
            .Which.ViewName.Should().Be("StepUp");
        _userManagerMock.Verify(
            x => x.GenerateNewTwoFactorRecoveryCodesAsync(It.IsAny<ApplicationUser>(), It.IsAny<int>()),
            Times.Never);
    }

    [Fact]
    public async Task GenerateRecoveryCodes_Post_WrongPassword_DoesNotGenerate()
    {
        ArrangeValidStepUp();

        var result = await _controller.GenerateRecoveryCodes(new TwoFactorStepUpViewModel
        {
            CurrentPassword = "WrongPassword1!",
            TwoFactorCode = CorrectCode,
        });

        result.Should().BeOfType<ViewResult>().Which.ViewName.Should().Be("StepUp");
        _userManagerMock.Verify(
            x => x.GenerateNewTwoFactorRecoveryCodesAsync(It.IsAny<ApplicationUser>(), It.IsAny<int>()),
            Times.Never);
    }

    [Fact]
    public async Task GenerateRecoveryCodes_Post_WrongAuthenticatorCode_DoesNotGenerate()
    {
        // The password alone must not be enough while 2FA is on — otherwise a
        // leaked password plus a stolen cookie still strips the second factor.
        ArrangeValidStepUp();

        var result = await _controller.GenerateRecoveryCodes(new TwoFactorStepUpViewModel
        {
            CurrentPassword = CorrectPassword,
            TwoFactorCode = "000000",
        });

        result.Should().BeOfType<ViewResult>().Which.ViewName.Should().Be("StepUp");
        _userManagerMock.Verify(
            x => x.GenerateNewTwoFactorRecoveryCodesAsync(It.IsAny<ApplicationUser>(), It.IsAny<int>()),
            Times.Never);
    }

    [Fact]
    public async Task GenerateRecoveryCodes_Post_ValidStepUp_ReturnsTheCodes()
    {
        ArrangeValidStepUp();
        var codes = new[] { "C1", "C2", "C3" };
        _userManagerMock.Setup(x => x.GenerateNewTwoFactorRecoveryCodesAsync(_testUser, 10))
            .ReturnsAsync(codes);

        var result = await _controller.GenerateRecoveryCodes(ValidStepUp());

        var view = result.Should().BeOfType<ViewResult>().Subject;
        view.ViewName.Should().Be("ShowRecoveryCodes");
        view.Model.Should().BeOfType<ShowRecoveryCodesViewModel>()
            .Which.RecoveryCodes.Should().BeEquivalentTo(codes);
    }

    [Fact]
    public async Task Disable2faConfirmed_WithoutStepUp_DoesNotDisable()
    {
        ArrangeValidStepUp();

        var result = await _controller.Disable2faConfirmed(new TwoFactorStepUpViewModel
        {
            CurrentPassword = "WrongPassword1!",
        });

        result.Should().BeOfType<ViewResult>().Which.ViewName.Should().Be("StepUp");
        _userManagerMock.Verify(
            x => x.SetTwoFactorEnabledAsync(It.IsAny<ApplicationUser>(), false), Times.Never);
    }

    [Fact]
    public async Task Disable2faConfirmed_ValidStepUp_Disables2faAndResetsKey()
    {
        ArrangeValidStepUp();
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, false))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.ResetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _controller.Disable2faConfirmed(ValidStepUp());

        result.Should().BeOfType<RedirectToActionResult>();
        _userManagerMock.Verify(x => x.SetTwoFactorEnabledAsync(_testUser, false), Times.Once);
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(_testUser), Times.Once);
    }

    [Fact]
    public async Task Disable2faConfirmed_UserNotFound_ReturnsNotFound()
    {
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _controller.Disable2faConfirmed(ValidStepUp());

        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task ResetAuthenticator_Get_DoesNotResetAnything()
    {
        ArrangeValidStepUp();

        var result = await _controller.ResetAuthenticator();

        result.Should().BeOfType<ViewResult>().Which.ViewName.Should().Be("StepUp");
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task ResetAuthenticator_Post_WithoutStepUp_DoesNotReset()
    {
        // The attack this closes: a stolen cookie swapping the authenticator
        // secret over to the attacker's device.
        ArrangeValidStepUp();

        var result = await _controller.ResetAuthenticator(new TwoFactorStepUpViewModel
        {
            CurrentPassword = "WrongPassword1!",
            TwoFactorCode = CorrectCode,
        });

        result.Should().BeOfType<ViewResult>().Which.ViewName.Should().Be("StepUp");
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task ResetAuthenticator_Post_ValidStepUp_Disables2faAndResetsKey()
    {
        ArrangeValidStepUp();
        _userManagerMock.Setup(x => x.SetTwoFactorEnabledAsync(_testUser, false))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.ResetAuthenticatorKeyAsync(_testUser))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _controller.ResetAuthenticator(ValidStepUp());

        result.Should().BeOfType<RedirectToActionResult>();
        _userManagerMock.Verify(x => x.SetTwoFactorEnabledAsync(_testUser, false), Times.Once);
        _userManagerMock.Verify(x => x.ResetAuthenticatorKeyAsync(_testUser), Times.Once);
    }

    [Fact]
    public async Task ResetAuthenticator_Post_UserNotFound_ReturnsNotFound()
    {
        _userManagerMock.Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _controller.ResetAuthenticator(ValidStepUp());

        result.Should().BeOfType<NotFoundResult>();
    }
}
