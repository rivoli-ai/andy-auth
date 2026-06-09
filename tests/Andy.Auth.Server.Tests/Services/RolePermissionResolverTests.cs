using Andy.Auth.Server.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// Covers the interim role→permission projection that emits the flat
/// <c>permission</c> claims downstream services authorize on (e.g.
/// andy-tasks <c>tasks:approvePlan</c>). Regression for the gap where NO
/// token carried a <c>permission</c> claim, so the andy-tasks
/// human-verification approve/reject endpoints 403'd for every user.
/// </summary>
public class RolePermissionResolverTests
{
    private static RolePermissionResolver Make(Dictionary<string, List<string>> map)
        => new(Options.Create(new RolePermissionOptions { RolePermissions = map }));

    [Fact]
    public void Resolve_MapsRoleToItsGrantedPermissions()
    {
        var resolver = Make(new()
        {
            ["User"] = new() { "tasks:approvePlan", "tasks:editPlan" },
        });

        var permissions = resolver.Resolve(new[] { "User" });

        Assert.Contains("tasks:approvePlan", permissions);
        Assert.Contains("tasks:editPlan", permissions);
    }

    [Fact]
    public void Resolve_IsCaseInsensitiveOnRoleName()
    {
        // Config authored as "Admin"; Identity may surface "admin".
        var resolver = Make(new()
        {
            ["Admin"] = new() { "tasks:approvePlan" },
        });

        Assert.Contains("tasks:approvePlan", resolver.Resolve(new[] { "admin" }));
    }

    [Fact]
    public void Resolve_UnionsAndDeduplicatesAcrossRoles()
    {
        var resolver = Make(new()
        {
            ["Admin"] = new() { "tasks:approvePlan", "tasks:editPlan" },
            ["User"] = new() { "tasks:approvePlan" },
        });

        var permissions = resolver.Resolve(new[] { "Admin", "User" });

        Assert.Equal(2, permissions.Count);
        Assert.Contains("tasks:approvePlan", permissions);
        Assert.Contains("tasks:editPlan", permissions);
    }

    [Fact]
    public void Resolve_UnmappedRole_YieldsNoPermissions()
    {
        var resolver = Make(new()
        {
            ["Admin"] = new() { "tasks:approvePlan" },
        });

        Assert.Empty(resolver.Resolve(new[] { "Viewer" }));
    }

    [Fact]
    public void Resolve_EmptyMap_YieldsNoPermissions()
    {
        Assert.Empty(Make(new()).Resolve(new[] { "User", "Admin" }));
    }

    [Fact]
    public void Resolve_SkipsBlankPermissionEntries()
    {
        var resolver = Make(new()
        {
            ["User"] = new() { "tasks:approvePlan", "", "  " },
        });

        Assert.Equal(new[] { "tasks:approvePlan" }, resolver.Resolve(new[] { "User" }));
    }
}
