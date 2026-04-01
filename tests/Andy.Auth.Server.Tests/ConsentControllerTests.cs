using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace Andy.Auth.Server.Tests;

public class ConsentControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<IOpenIddictApplicationManager> _applicationManagerMock;
    private readonly Mock<IOpenIddictScopeManager> _scopeManagerMock;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<ILogger<ConsentController>> _loggerMock;
    private readonly ConsentController _controller;
    private readonly string _testUserId = "test-user-id";

    public ConsentControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        _applicationManagerMock = new Mock<IOpenIddictApplicationManager>();
        _scopeManagerMock = new Mock<IOpenIddictScopeManager>();
        _loggerMock = new Mock<ILogger<ConsentController>>();

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _controller = new ConsentController(
            _applicationManagerMock.Object,
            _scopeManagerMock.Object,
            _context,
            _userManagerMock.Object,
            _loggerMock.Object);

        SetupHttpContext();
    }

    private void SetupHttpContext()
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, _testUserId),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);

        var httpContext = new DefaultHttpContext { User = principal };
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        _controller.TempData = new TempDataDictionary(httpContext, Mock.Of<ITempDataProvider>());
        _userManagerMock.Setup(x => x.GetUserId(principal)).Returns(_testUserId);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== Index GET Tests ====================

    [Fact]
    public async Task Index_Get_MissingReturnUrl_ReturnsBadRequest()
    {
        // Act
        var result = await _controller.Index(returnUrl: null!);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequest.Value.Should().Be("Return URL is required.");
    }

    [Fact]
    public async Task Index_Get_EmptyReturnUrl_ReturnsBadRequest()
    {
        // Act
        var result = await _controller.Index(returnUrl: "");

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Index_Get_NoQueryString_ReturnsBadRequest()
    {
        // Act
        var result = await _controller.Index(returnUrl: "/authorize");

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Index_Get_MissingClientId_ReturnsBadRequest()
    {
        // Act
        var result = await _controller.Index(returnUrl: "/authorize?scope=openid");

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Index_Get_ClientNotFound_ReturnsBadRequest()
    {
        // Arrange
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("unknown-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        // Act
        var result = await _controller.Index(returnUrl: "/authorize?client_id=unknown-client&scope=openid");

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Index_Get_ValidRequest_ReturnsConsentView()
    {
        // Arrange
        var mockApplication = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Application");

        // Act
        var result = await _controller.Index(returnUrl: "/authorize?client_id=test-client&scope=openid profile email");

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<ConsentViewModel>().Subject;
        model.ClientId.Should().Be("test-client");
        model.ClientName.Should().Be("Test Application");
        model.RequestedScopes.Should().HaveCount(3);
    }

    [Fact]
    public async Task Index_Get_StandardScopes_HaveFriendlyDescriptions()
    {
        // Arrange
        var mockApplication = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Application");

        // Act
        var result = await _controller.Index(returnUrl: "/authorize?client_id=test-client&scope=openid profile email offline_access");

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<ConsentViewModel>().Subject;

        var openidScope = model.RequestedScopes.First(s => s.Value == "openid");
        openidScope.DisplayName.Should().Be("OpenID");
        openidScope.Required.Should().BeTrue();

        var profileScope = model.RequestedScopes.First(s => s.Value == "profile");
        profileScope.DisplayName.Should().Be("Profile");

        var emailScope = model.RequestedScopes.First(s => s.Value == "email");
        emailScope.DisplayName.Should().Be("Email");

        var offlineScope = model.RequestedScopes.First(s => s.Value == "offline_access");
        offlineScope.DisplayName.Should().Be("Offline Access");
    }

    [Fact]
    public async Task Index_Get_CustomScope_GetsDescriptionFromScopeManager()
    {
        // Arrange
        var mockApplication = new object();
        var mockScope = new object();

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Application");

        _scopeManagerMock.Setup(x => x.FindByNameAsync("custom_scope", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockScope);
        _scopeManagerMock.Setup(x => x.GetDisplayNameAsync(mockScope, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Custom Scope Display");
        _scopeManagerMock.Setup(x => x.GetDescriptionAsync(mockScope, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Custom scope description");

        // Act
        var result = await _controller.Index(returnUrl: "/authorize?client_id=test-client&scope=openid custom_scope");

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeOfType<ConsentViewModel>().Subject;

        var customScope = model.RequestedScopes.First(s => s.Value == "custom_scope");
        customScope.DisplayName.Should().Be("Custom Scope Display");
        customScope.Description.Should().Be("Custom scope description");
    }

    // ==================== Index POST Tests ====================

    [Fact]
    public async Task Index_Post_UserDenies_RedirectsWithError()
    {
        // Arrange
        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize?client_id=test-client&scope=openid",
            Decision = "deny"
        };

        // Act
        var result = await _controller.Index(model);

        // Assert
        var redirect = result.Should().BeOfType<RedirectResult>().Subject;
        redirect.Url.Should().Contain("error=access_denied");
        redirect.Url.Should().Contain("error_description=");
    }

    [Fact]
    public async Task Index_Post_UserAllows_SavesConsent()
    {
        // Arrange
        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize?client_id=test-client&scope=openid profile",
            Decision = "allow",
            ScopesConsented = new List<string> { "openid", "profile" },
            RememberConsent = true
        };

        // Act
        var result = await _controller.Index(model);

        // Assert
        var redirect = result.Should().BeOfType<RedirectResult>().Subject;
        redirect.Url.Should().Contain("consent_granted=true");

        var savedConsent = await _context.UserConsents
            .FirstOrDefaultAsync(c => c.UserId == _testUserId && c.ClientId == "test-client");
        savedConsent.Should().NotBeNull();
        savedConsent!.ScopesList.Should().Contain("openid");
        savedConsent.ScopesList.Should().Contain("profile");
        savedConsent.RememberConsent.Should().BeTrue();
        savedConsent.ExpiresAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Index_Post_NoRemember_ConsentDoesNotExpire()
    {
        // Arrange
        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize?client_id=test-client&scope=openid",
            Decision = "allow",
            ScopesConsented = new List<string> { "openid" },
            RememberConsent = false
        };

        // Act
        await _controller.Index(model);

        // Assert
        var savedConsent = await _context.UserConsents
            .FirstOrDefaultAsync(c => c.UserId == _testUserId && c.ClientId == "test-client");
        savedConsent.Should().NotBeNull();
        savedConsent!.RememberConsent.Should().BeFalse();
        savedConsent.ExpiresAt.Should().BeNull();
    }

    [Fact]
    public async Task Index_Post_UpdatesExistingConsent()
    {
        // Arrange
        var existingConsent = new UserConsent
        {
            UserId = _testUserId,
            ClientId = "test-client",
            RememberConsent = false,
            GrantedAt = DateTime.UtcNow.AddDays(-30)
        };
        existingConsent.SetScopes(new List<string> { "openid" });
        _context.UserConsents.Add(existingConsent);
        await _context.SaveChangesAsync();

        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize?client_id=test-client&scope=openid profile email",
            Decision = "allow",
            ScopesConsented = new List<string> { "openid", "profile", "email" },
            RememberConsent = true
        };

        // Act
        await _controller.Index(model);

        // Assert
        var consents = await _context.UserConsents
            .Where(c => c.UserId == _testUserId && c.ClientId == "test-client")
            .ToListAsync();
        consents.Should().ContainSingle();
        consents[0].ScopesList.Should().HaveCount(3);
        consents[0].RememberConsent.Should().BeTrue();
    }

    [Fact]
    public async Task Index_Post_AutoIncludesOpenIdScope()
    {
        // Arrange
        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize?client_id=test-client&scope=openid profile",
            Decision = "allow",
            ScopesConsented = new List<string> { "profile" }, // User didn't check openid but it was requested
            RememberConsent = false
        };

        // Act
        await _controller.Index(model);

        // Assert
        var savedConsent = await _context.UserConsents
            .FirstOrDefaultAsync(c => c.UserId == _testUserId && c.ClientId == "test-client");
        savedConsent!.ScopesList.Should().Contain("openid");
        savedConsent.ScopesList.Should().Contain("profile");
    }

    [Fact]
    public async Task Index_Post_InvalidModelState_ReturnsView()
    {
        // Arrange
        var mockApplication = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("test-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Application");

        _controller.ModelState.AddModelError("test", "Test error");

        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize?client_id=test-client&scope=openid",
            Decision = "allow"
        };

        // Act
        var result = await _controller.Index(model);

        // Assert
        result.Should().BeOfType<ViewResult>();
    }

    [Fact]
    public async Task Index_Post_NoQueryString_ReturnsBadRequest()
    {
        // Arrange
        var model = new ConsentInputModel
        {
            ReturnUrl = "/authorize", // No query string
            Decision = "allow"
        };

        // Act
        var result = await _controller.Index(model);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    // ==================== MyConsents Tests ====================

    [Fact]
    public async Task MyConsents_NoConsents_ReturnsEmptyList()
    {
        // Act
        var result = await _controller.MyConsents();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeAssignableTo<List<UserConsentViewModel>>().Subject;
        model.Should().BeEmpty();
    }

    [Fact]
    public async Task MyConsents_WithConsents_ReturnsOrderedList()
    {
        // Arrange
        var consent1 = new UserConsent
        {
            UserId = _testUserId,
            ClientId = "client-1",
            GrantedAt = DateTime.UtcNow.AddDays(-2),
            RememberConsent = true
        };
        consent1.SetScopes(new List<string> { "openid" });

        var consent2 = new UserConsent
        {
            UserId = _testUserId,
            ClientId = "client-2",
            GrantedAt = DateTime.UtcNow.AddDays(-1),
            RememberConsent = false
        };
        consent2.SetScopes(new List<string> { "openid", "profile" });

        _context.UserConsents.AddRange(consent1, consent2);
        await _context.SaveChangesAsync();

        var mockApp1 = new object();
        var mockApp2 = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("client-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApp1);
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("client-2", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApp2);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApp1, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Application 1");
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApp2, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Application 2");

        // Act
        var result = await _controller.MyConsents();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeAssignableTo<List<UserConsentViewModel>>().Subject;
        model.Should().HaveCount(2);
        model[0].ClientId.Should().Be("client-2"); // Most recent first
        model[1].ClientId.Should().Be("client-1");
    }

    [Fact]
    public async Task MyConsents_ApplicationNotFound_UsesClientIdAsName()
    {
        // Arrange
        var consent = new UserConsent
        {
            UserId = _testUserId,
            ClientId = "deleted-client",
            GrantedAt = DateTime.UtcNow,
            RememberConsent = true
        };
        consent.SetScopes(new List<string> { "openid" });
        _context.UserConsents.Add(consent);
        await _context.SaveChangesAsync();

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync("deleted-client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        // Act
        var result = await _controller.MyConsents();

        // Assert
        var viewResult = result.Should().BeOfType<ViewResult>().Subject;
        var model = viewResult.Model.Should().BeAssignableTo<List<UserConsentViewModel>>().Subject;
        model[0].ClientName.Should().Be("deleted-client");
    }

    // ==================== Revoke Tests ====================

    [Fact]
    public async Task Revoke_ConsentNotFound_Returns404()
    {
        // Act
        var result = await _controller.Revoke(999);

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task Revoke_OtherUsersConsent_Returns404()
    {
        // Arrange
        var otherConsent = new UserConsent
        {
            UserId = "other-user",
            ClientId = "test-client",
            GrantedAt = DateTime.UtcNow,
            RememberConsent = true
        };
        otherConsent.SetScopes(new List<string> { "openid" });
        _context.UserConsents.Add(otherConsent);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.Revoke(otherConsent.Id);

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task Revoke_ValidConsent_DeletesAndRedirects()
    {
        // Arrange
        var consent = new UserConsent
        {
            UserId = _testUserId,
            ClientId = "test-client",
            GrantedAt = DateTime.UtcNow,
            RememberConsent = true
        };
        consent.SetScopes(new List<string> { "openid" });
        _context.UserConsents.Add(consent);
        await _context.SaveChangesAsync();
        var consentId = consent.Id;

        // Act
        var result = await _controller.Revoke(consentId);

        // Assert
        var redirect = result.Should().BeOfType<RedirectToActionResult>().Subject;
        redirect.ActionName.Should().Be("MyConsents");

        var deletedConsent = await _context.UserConsents.FindAsync(consentId);
        deletedConsent.Should().BeNull();

        _controller.TempData["Message"].Should().NotBeNull();
        ((string)_controller.TempData["Message"]!).Should().Contain("test-client");
    }

    [Fact]
    public async Task Revoke_ValidConsent_LogsRevocation()
    {
        // Arrange
        var consent = new UserConsent
        {
            UserId = _testUserId,
            ClientId = "logged-client",
            GrantedAt = DateTime.UtcNow,
            RememberConsent = true
        };
        consent.SetScopes(new List<string> { "openid" });
        _context.UserConsents.Add(consent);
        await _context.SaveChangesAsync();

        // Act
        await _controller.Revoke(consent.Id);

        // Assert
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("revoked consent")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}
