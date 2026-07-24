using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// andy-auth#146. `AuthorizationController` gates the authorization_code /
/// refresh_token / device_code path on `CanSignInAsync`, so overriding it is
/// what stops a refresh token outliving a suspension. These assert the
/// override actually fires for each lifecycle flag.
/// </summary>
public class AndyAuthSignInManagerTests
{
    private static AndyAuthSignInManager CreateSignInManager()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        var userManager = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        // Default IdentityOptions require no confirmed email/phone/account, so
        // the base implementation returns true without touching the store —
        // any false result therefore comes from our override.
        return new AndyAuthSignInManager(
            userManager.Object,
            new Mock<IHttpContextAccessor>().Object,
            ClaimsFactory(),
            Options.Create(new IdentityOptions()),
            new Mock<ILogger<SignInManager<ApplicationUser>>>().Object,
            new Mock<IAuthenticationSchemeProvider>().Object,
            new Mock<IUserConfirmation<ApplicationUser>>().Object);
    }

    /// <summary>
    /// `base.CreateUserPrincipalAsync` delegates straight to this, so it has to
    /// return a real principal for the session_id tests to have an identity to
    /// stamp.
    /// </summary>
    private static IUserClaimsPrincipalFactory<ApplicationUser> ClaimsFactory()
    {
        var factory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
        factory.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(() => new ClaimsPrincipal(
                new ClaimsIdentity(Array.Empty<Claim>(), "Identity.Application")));
        return factory.Object;
    }

    private static ApplicationUser HealthyUser() => new()
    {
        Id = "user-1",
        Email = "user@test.local",
        IsActive = true,
    };

    [Fact]
    public async Task CanSignInAsync_AllowsHealthyAccount()
    {
        var result = await CreateSignInManager().CanSignInAsync(HealthyUser());

        result.Should().BeTrue();
    }

    [Fact]
    public async Task CanSignInAsync_RefusesSuspendedAccount()
    {
        var user = HealthyUser();
        user.IsSuspended = true;

        var result = await CreateSignInManager().CanSignInAsync(user);

        result.Should().BeFalse("suspension must block token refresh, not just the login form");
    }

    [Fact]
    public async Task CanSignInAsync_RefusesExpiredAccount()
    {
        var user = HealthyUser();
        user.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);

        var result = await CreateSignInManager().CanSignInAsync(user);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanSignInAsync_RefusesSoftDeletedAccount()
    {
        var user = HealthyUser();
        user.DeletedAt = DateTime.UtcNow;

        var result = await CreateSignInManager().CanSignInAsync(user);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanSignInAsync_RefusesInactiveAccount()
    {
        var user = HealthyUser();
        user.IsActive = false;

        var result = await CreateSignInManager().CanSignInAsync(user);

        result.Should().BeFalse();
    }

    // ==================== andy-auth#154: session_id ====================

    [Fact]
    public async Task CreateUserPrincipalAsync_StampsASessionId()
    {
        // Nothing issued this claim before, so SessionTrackingMiddleware fell
        // back to hashing the auth cookie — which changes on every renewal.
        var principal = await CreateSignInManager().CreateUserPrincipalAsync(HealthyUser());

        principal.FindFirst(AndyAuthSignInManager.SessionIdClaimType)
            .Should().NotBeNull();
    }

    [Fact]
    public async Task CreateUserPrincipalAsync_CarriesForwardAnExistingSessionId()
    {
        // RefreshSignInAsync and the periodic security-stamp validation both
        // rebuild the principal. Minting a fresh id there would resurrect the
        // churn this fix removes, so the in-flight value wins.
        const string existing = "existing-session-id";

        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(AndyAuthSignInManager.SessionIdClaimType, existing) },
                "Identity.Application"))
        };
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(httpContext);

        var store = new Mock<IUserStore<ApplicationUser>>();
        var userManager = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        var signInManager = new AndyAuthSignInManager(
            userManager.Object,
            accessor.Object,
            ClaimsFactory(),
            Options.Create(new IdentityOptions()),
            new Mock<ILogger<SignInManager<ApplicationUser>>>().Object,
            new Mock<IAuthenticationSchemeProvider>().Object,
            new Mock<IUserConfirmation<ApplicationUser>>().Object);

        var principal = await signInManager.CreateUserPrincipalAsync(HealthyUser());

        principal.FindFirst(AndyAuthSignInManager.SessionIdClaimType)!.Value
            .Should().Be(existing);
    }

    [Fact]
    public async Task CreateUserPrincipalAsync_MintsDistinctIdsForDistinctSignIns()
    {
        var first = await CreateSignInManager().CreateUserPrincipalAsync(HealthyUser());
        var second = await CreateSignInManager().CreateUserPrincipalAsync(HealthyUser());

        first.FindFirst(AndyAuthSignInManager.SessionIdClaimType)!.Value
            .Should().NotBe(second.FindFirst(AndyAuthSignInManager.SessionIdClaimType)!.Value);
    }
}
