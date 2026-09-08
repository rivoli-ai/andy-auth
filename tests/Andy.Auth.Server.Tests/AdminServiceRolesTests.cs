using System.Security.Claims;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Andy.Auth.Server.Tests;

public sealed class AdminServiceRolesTests : IDisposable
{
    private readonly ServiceProvider _provider;
    private readonly UserManager<ApplicationUser> _users;
    private readonly RoleManager<IdentityRole> _roles;
    private readonly Mock<IUserAccessRevoker> _revoker = new();
    private readonly Mock<IAuditService> _audit = new();
    private readonly AdminServiceRolesController _controller;

    public AdminServiceRolesTests()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddIdentityCore<ApplicationUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();
        _provider = services.BuildServiceProvider();
        _users = _provider.GetRequiredService<UserManager<ApplicationUser>>();
        _roles = _provider.GetRequiredService<RoleManager<IdentityRole>>();
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "admin") }, "test"))
        };
        _controller = new AdminServiceRolesController(_users, _roles, _audit.Object, _revoker.Object)
        {
            ControllerContext = new ControllerContext { HttpContext = context },
            TempData = new TempDataDictionary(context, Mock.Of<ITempDataProvider>())
        };
    }

    public void Dispose() => _provider.Dispose();

    [Fact]
    public async Task CreateGrantRemove_PreservesOtherRoles_AndRevokesStaleAccess()
    {
        var user = new ApplicationUser { UserName = "person", Email = "person@example.test" };
        (await _users.CreateAsync(user)).Succeeded.Should().BeTrue();
        await _roles.CreateAsync(new IdentityRole("User"));
        await _users.AddToRoleAsync(user, "User");
        await _controller.Create(user.Id, "AHP Viewer");
        await _controller.Create(user.Id, "AHP Reviewer");
        await _controller.Grant(user.Id, "AHP Viewer");
        await _controller.Grant(user.Id, "AHP Reviewer");
        (await _users.GetRolesAsync(user)).Should().BeEquivalentTo("User", "AHP Viewer", "AHP Reviewer");
        await _controller.Remove(user.Id, "AHP Viewer");
        (await _users.GetRolesAsync(user)).Should().BeEquivalentTo("User", "AHP Reviewer");
        _revoker.Verify(r => r.RevokeAllAccessAsync(user, "Service role membership changed"), Times.Exactly(3));
        _audit.Verify(a => a.LogAsync("ServiceRoleRemoved", "admin", "unknown", user.Id, user.Email,
            "Service role: AHP Viewer", null), Times.Once);
        var view = (ViewResult)await _controller.Index(user.Id);
        var model = (AdminServiceRolesController.RolePage)view.Model!;
        model.Available.Should().BeEquivalentTo("AHP Viewer", "AHP Reviewer");
        model.Assigned.Should().Contain("AHP Reviewer");
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("ADMIN")]
    [InlineData("User")]
    public async Task ServiceRoleActionsCannotChangeBuiltIns(string name)
    {
        var user = new ApplicationUser { UserName = "admin-person" };
        await _users.CreateAsync(user);
        await _roles.CreateAsync(new IdentityRole("Admin"));
        await _users.AddToRoleAsync(user, "Admin");
        await _controller.Create(user.Id, name);
        await _controller.Grant(user.Id, name);
        await _controller.Remove(user.Id, name);
        (await _users.GetRolesAsync(user)).Should().BeEquivalentTo("Admin");
        _revoker.Verify(r => r.RevokeAllAccessAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task InvalidOrDuplicateRoleAndUnknownGrant_DoNotReportSuccess()
    {
        var user = new ApplicationUser { UserName = "person" };
        await _users.CreateAsync(user);
        await _controller.Create(user.Id, "AHP Viewer");
        _controller.TempData.Clear();
        await _controller.Create(user.Id, "ahp viewer");
        _controller.TempData.Should().ContainKey("ErrorMessage").And.NotContainKey("SuccessMessage");
        await _controller.Create(user.Id, " ");
        await _controller.Grant(user.Id, "missing");
        (await _users.GetRolesAsync(user)).Should().BeEmpty();
        _roles.Roles.Should().HaveCount(1);
    }

    [Fact]
    public void ControllerRequiresAdminCookieAndAntiforgery()
    {
        var policy = typeof(AdminServiceRolesController).GetCustomAttributes(typeof(AuthorizeAttribute), false)
            .Cast<AuthorizeAttribute>().Single();
        policy.Roles.Should().Be("Admin");
        policy.AuthenticationSchemes.Should().Be("Identity.Application");
        typeof(AdminServiceRolesController).IsDefined(typeof(AutoValidateAntiforgeryTokenAttribute), false).Should().BeTrue();
    }
}
