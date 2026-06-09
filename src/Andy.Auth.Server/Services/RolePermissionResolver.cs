using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Maps a signed-in user's role bindings to the flat <c>permission</c>
/// claim strings that downstream services authorize on (e.g. andy-tasks'
/// <c>tasks:approvePlan</c> / <c>tasks:editPlan</c> policies, which do
/// <c>RequireClaim("permission", …)</c>).
/// </summary>
/// <remarks>
/// Interim role→permission projection until the full AL-rbac roll-out
/// sources effective permissions from andy-rbac. The map is config-driven
/// (<c>Authorization:RolePermissions</c>) so a deployment can tighten or
/// extend it without a code change. andy-auth has no user-permission store
/// of its own — permissions are coarse capability strings consumed by the
/// owning service's policy, not andy-rbac's <c>app:resource:action</c>
/// permission model.
/// </remarks>
public sealed class RolePermissionOptions
{
    public const string SectionName = "Authorization";

    /// <summary>Role name → granted permission strings.</summary>
    public Dictionary<string, List<string>> RolePermissions { get; set; } = new();
}

/// <summary>Resolves the union of permission strings granted by a set of roles.</summary>
public sealed class RolePermissionResolver
{
    private readonly RolePermissionOptions _options;

    public RolePermissionResolver(IOptions<RolePermissionOptions> options)
    {
        _options = options.Value;
    }

    /// <summary>
    /// Returns the de-duplicated, deterministically-ordered set of
    /// permission strings granted by <paramref name="roles"/>. Role lookup
    /// is case-insensitive so config casing ("Admin") matches the Identity
    /// role casing regardless of how the map was authored.
    /// </summary>
    public IReadOnlyCollection<string> Resolve(IEnumerable<string> roles)
    {
        var permissions = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var role in roles)
        {
            var match = _options.RolePermissions
                .FirstOrDefault(kvp => string.Equals(kvp.Key, role, StringComparison.OrdinalIgnoreCase));
            if (match.Value is null)
            {
                continue;
            }

            foreach (var permission in match.Value)
            {
                if (!string.IsNullOrWhiteSpace(permission))
                {
                    permissions.Add(permission.Trim());
                }
            }
        }

        return permissions;
    }
}
