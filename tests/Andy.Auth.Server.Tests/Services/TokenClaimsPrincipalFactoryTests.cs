using System.Security.Claims;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// andy-auth#149. The auth-code and device flows each carried their own copy
/// of the claims-principal build and drifted: the role→`permission` projection
/// landed in one copy only, so device-flow tokens reached downstream services
/// with no `permission` claim and every RequireClaim("permission", …) policy
/// rejected them. These assert the single shared implementation emits the full
/// claim set regardless of which flow calls it.
/// </summary>
public class TokenClaimsPrincipalFactoryTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly Mock<UserManager<ApplicationUser>> _userManager;
    private readonly Mock<SignInManager<ApplicationUser>> _signInManager;
    private readonly Mock<IOpenIddictScopeManager> _scopeManager;
    private readonly TokenClaimsPrincipalFactory _factory;

    private static readonly ApplicationUser User = new()
    {
        Id = "user-1",
        Email = "user@test.local",
        UserName = "user@test.local",
        FullName = "Test User",
        EmailConfirmed = true,
        IsActive = true,
    };

    public TokenClaimsPrincipalFactoryTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"TestDb_{Guid.NewGuid()}")
            .Options;
        _dbContext = new ApplicationDbContext(options);

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManager = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        _userManager.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "User" });

        _signInManager = new Mock<SignInManager<ApplicationUser>>(
            _userManager.Object,
            new Mock<IHttpContextAccessor>().Object,
            new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>().Object,
            null!, null!, null!, null!);
        _signInManager.Setup(x => x.CreateUserPrincipalAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(() => new ClaimsPrincipal(new ClaimsIdentity(
                Array.Empty<Claim>(), "Identity.Application", Claims.Name, Claims.Role)));

        _scopeManager = new Mock<IOpenIddictScopeManager>();
        _scopeManager.Setup(x => x.ListResourcesAsync(It.IsAny<System.Collections.Immutable.ImmutableArray<string>>(), default))
            .Returns(AsyncEmpty<string>());

        var rolePermissions = Options.Create(new RolePermissionOptions
        {
            RolePermissions = new Dictionary<string, List<string>>
            {
                ["User"] = new() { "tasks:approvePlan", "tasks:editPlan" },
            }
        });

        _factory = new TokenClaimsPrincipalFactory(
            _signInManager.Object,
            _userManager.Object,
            new Mock<IOpenIddictApplicationManager>().Object,
            new Mock<IOpenIddictAuthorizationManager>().Object,
            _scopeManager.Object,
            new RolePermissionResolver(rolePermissions),
            _dbContext,
            DeploymentTenant.Resolve(TenantConfiguration));
    }

    /// <summary>
    /// Pins the tenant so the assertions below can name it. A deployment
    /// resolves this once from its own configuration; nothing in a request
    /// reaches it.
    /// </summary>
    private const string Tenant = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    private static IConfiguration TenantConfiguration =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [DeploymentTenant.ConfigurationKey] = Tenant,
            })
            .Build();

    private static async IAsyncEnumerable<T> AsyncEmpty<T>()
    {
        await Task.CompletedTask;
        yield break;
    }

    [Theory]
    // The client_id argument is the only thing that ever differed between the
    // two copies: the auth-code flow reads it off the OpenIddict request, the
    // device flow off the principal resolved from the user code.
    [InlineData(null)]              // auth-code request with no client_id resolved
    [InlineData("andy-cli")]        // device flow
    public async Task CreateAsync_EmitsPermissionClaims_ForEveryFlow(string? clientId)
    {
        var principal = await _factory.CreateAsync(User, new[] { "openid", "roles" }, clientId);

        principal.FindAll("permission").Select(c => c.Value)
            .Should().BeEquivalentTo("tasks:approvePlan", "tasks:editPlan");
    }

    [Fact]
    public async Task CreateAsync_RoutesPermissionClaimsToAccessTokenOnly()
    {
        // The identity token is for the client/UI; permissions are for
        // downstream service policies.
        var principal = await _factory.CreateAsync(User, new[] { "openid", "roles" }, "andy-cli");

        var permission = principal.FindFirst("permission");
        permission.Should().NotBeNull();
        permission!.GetDestinations().Should().BeEquivalentTo(Destinations.AccessToken);
    }

    [Fact]
    public async Task CreateAsync_EmitsActiveGroupClaims()
    {
        var group = new Group { Code = "engineering", Name = "Engineering", IsActive = true };
        _dbContext.Groups.Add(group);
        _dbContext.UserGroups.Add(new UserGroup { UserId = User.Id, Group = group });
        await _dbContext.SaveChangesAsync();

        var principal = await _factory.CreateAsync(User, new[] { "openid", "roles" }, "andy-cli");

        principal.FindAll("groups").Select(c => c.Value).Should().BeEquivalentTo("engineering");
    }

    [Fact]
    public async Task CreateAsync_NeverLeaksSecurityStamp()
    {
        _signInManager.Setup(x => x.CreateUserPrincipalAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(() => new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("AspNet.Identity.SecurityStamp", "secret-value") },
                "Identity.Application", Claims.Name, Claims.Role)));

        var principal = await _factory.CreateAsync(User, new[] { "openid" }, "andy-cli");

        principal.FindFirst("AspNet.Identity.SecurityStamp")!
            .GetDestinations().Should().BeEmpty();
    }

    [Fact]
    public async Task CreateAsync_EmitsCoreSubjectClaims()
    {
        var principal = await _factory.CreateAsync(
            User, new[] { "openid", "profile", "email" }, "andy-cli");

        principal.FindFirst(Claims.Subject)!.Value.Should().Be(User.Id);
        principal.FindFirst(Claims.Subject)!.GetDestinations()
            .Should().BeEquivalentTo(Destinations.AccessToken, Destinations.IdentityToken);
        principal.FindFirst(Claims.Email)!.Value.Should().Be(User.Email);
        principal.FindFirst(Claims.PreferredUsername)!.Value.Should().Be(User.UserName);
    }

    [Fact]
    public async Task CreateAsync_ProfileScope_DoesNotReleaseEmailAddress()
    {
        var principal = await _factory.CreateAsync(
            User, new[] { "openid", "profile" }, "andy-cli");

        principal.FindFirst(Claims.Email).Should().BeNull();
        principal.FindFirst(Claims.EmailVerified).Should().BeNull();
        principal.FindFirst(Claims.PreferredUsername).Should().BeNull(
            "the local username is the email address and must not bypass the email scope");
        principal.FindFirst(Claims.Name).Should().NotBeNull();
    }

    [Fact]
    public async Task CreateAsync_EmailScope_DoesNotReleaseProfileClaims()
    {
        var principal = await _factory.CreateAsync(
            User, new[] { "openid", "email" }, "andy-cli");

        principal.FindFirst(Claims.Email)!.Value.Should().Be(User.Email);
        principal.FindFirst(Claims.EmailVerified)!.Value.Should().Be("true");
        principal.FindFirst(Claims.Name).Should().BeNull();
        principal.FindFirst(Claims.PreferredUsername).Should().BeNull();
    }

    [Fact]
    public async Task CreateAsync_WithoutRolesScope_DoesNotReleaseAuthorityClaims()
    {
        var group = new Group { Code = "engineering", Name = "Engineering", IsActive = true };
        _dbContext.Groups.Add(group);
        _dbContext.UserGroups.Add(new UserGroup { UserId = User.Id, Group = group });
        await _dbContext.SaveChangesAsync();

        var principal = await _factory.CreateAsync(
            User, new[] { "openid", "profile" }, "andy-cli");

        principal.FindAll(Claims.Role).Should().BeEmpty();
        principal.FindAll("groups").Should().BeEmpty();
        principal.FindAll("permission").Should().BeEmpty();
    }

    [Fact]
    public async Task CreateAsync_UnverifiedEmail_IsExplicitlyMarkedUnverified()
    {
        var unverified = new ApplicationUser
        {
            Id = "unverified",
            Email = "unverified@test.local",
            UserName = "unverified@test.local",
            EmailConfirmed = false,
            IsActive = true
        };

        var principal = await _factory.CreateAsync(
            unverified, new[] { "openid", "email" }, "andy-cli");

        principal.FindFirst(Claims.EmailVerified)!.Value.Should().Be("false");
    }

    [Fact]
    public async Task CreateAsync_EmitsTheDeploymentTenantClaim()
    {
        var principal = await _factory.CreateAsync(User, new[] { "openid", "profile" }, "andy-cli");

        principal.FindAll(DeploymentTenant.ClaimType).Select(c => c.Value)
            .Should().BeEquivalentTo(Tenant);
    }

    [Fact]
    public async Task CreateAsync_RoutesTheTenantClaimToBothTokens()
    {
        // Resource servers partition storage on it, and a client that shows
        // which tenant it signed into reads the identity token.
        var principal = await _factory.CreateAsync(User, new[] { "openid", "profile" }, "andy-cli");

        principal.FindFirst(DeploymentTenant.ClaimType)!.GetDestinations()
            .Should().BeEquivalentTo(Destinations.AccessToken, Destinations.IdentityToken);
    }

    [Fact]
    public async Task CreateAsync_DiscardsATenantClaimAlreadyOnThePrincipal()
    {
        // A `tid` reaching the principal from a persisted user claim or from an
        // upstream provider surviving an external sign-in would otherwise let
        // whoever controls that directory pick the partition their tokens read
        // and write.
        _signInManager.Setup(x => x.CreateUserPrincipalAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(() => new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(DeploymentTenant.ClaimType, "11111111-1111-1111-1111-111111111111") },
                "Identity.Application", Claims.Name, Claims.Role)));

        var principal = await _factory.CreateAsync(User, new[] { "openid" }, "andy-cli");

        principal.FindAll(DeploymentTenant.ClaimType).Select(c => c.Value)
            .Should().BeEquivalentTo(Tenant);
    }
}
