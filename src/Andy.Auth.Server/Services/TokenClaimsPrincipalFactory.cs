using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Builds the <see cref="ClaimsPrincipal"/> that OpenIddict turns into an
/// access/identity token, for every user-bearing grant.
/// </summary>
/// <remarks>
/// <para>
/// andy-auth#149. <c>AuthorizationController</c> and <c>DeviceController</c>
/// each carried their own copy of this logic — the device one introduced
/// deliberately, "to avoid disturbing the existing auth-code flow in this PR".
/// The copies then drifted: when the role→<c>permission</c> projection landed
/// it went into the auth-code copy only, so device-flow tokens carried
/// <c>groups</c> but no <c>permission</c>, and every downstream endpoint doing
/// <c>RequireClaim("permission", …)</c> rejected device-flow users.
/// </para>
/// <para>
/// One implementation now serves both. The only thing that differed
/// structurally is where <c>client_id</c> comes from — the auth-code flow
/// reads it off the OpenIddict server request, the device flow off the
/// principal resolved from the user code — so it is a parameter.
/// </para>
/// </remarks>
public class TokenClaimsPrincipalFactory
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly RolePermissionResolver _rolePermissionResolver;
    private readonly ApplicationDbContext _dbContext;
    private readonly DeploymentTenant _tenant;

    public TokenClaimsPrincipalFactory(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        RolePermissionResolver rolePermissionResolver,
        ApplicationDbContext dbContext,
        DeploymentTenant tenant)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _rolePermissionResolver = rolePermissionResolver;
        _dbContext = dbContext;
        _tenant = tenant;
    }

    /// <summary>
    /// Creates the principal for <paramref name="user"/> with the granted
    /// <paramref name="scopes"/>, attaching a permanent authorization for
    /// <paramref name="clientId"/> when one is supplied.
    /// </summary>
    public async Task<ClaimsPrincipal> CreateAsync(
        ApplicationUser user,
        IEnumerable<string> scopes,
        string? clientId)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        var identity = (ClaimsIdentity)principal.Identity!;

        // The tenant is the deployment's, and only the deployment's. Any `tid`
        // already on the principal came from somewhere else — a claim persisted
        // against the user row, or an upstream provider's own tenant surviving
        // an external sign-in — and honouring it would let a caller who
        // controls that upstream directory choose the partition their tokens
        // read and write. Drop whatever is there before stating ours.
        foreach (var carrier in principal.Identities)
        {
            foreach (var stale in carrier.FindAll(DeploymentTenant.ClaimType).ToList())
            {
                carrier.TryRemoveClaim(stale);
            }
        }

        identity.AddClaim(new Claim(DeploymentTenant.ClaimType, _tenant.ClaimValue));

        // Claims persisted into the tokens.
        identity.AddClaim(new Claim(Claims.Subject, user.Id)
            .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.Email, user.Email!)
            .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.Name, user.FullName ?? user.UserName ?? user.Email!)
            .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.PreferredUsername, user.UserName ?? user.Email!)
            .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

        // Group claims for RBAC integration.
        foreach (var groupCode in await GetUserGroupsAsync(user.Id))
        {
            identity.AddClaim(new Claim("groups", groupCode)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        }

        // Permission claims for RBAC integration. Downstream services
        // authorize on a flat `permission` claim — e.g. andy-tasks'
        // tasks:approvePlan / tasks:editPlan policies do
        // RequireClaim("permission", …). Project the principal's role bindings
        // onto the permission strings those roles grant
        // (Authorization:RolePermissions config). Interim until the full
        // AL-rbac roll-out sources effective permissions from andy-rbac.
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var permission in _rolePermissionResolver.Resolve(roles))
        {
            identity.AddClaim(new Claim("permission", permission)
                .SetDestinations(Destinations.AccessToken));
        }

        principal.SetScopes(scopes);

        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(principal.GetScopes()))
        {
            resources.Add(resource);
        }
        principal.SetResources(resources);

        // Create or reuse a permanent authorization for this (user, client,
        // scopes). Authorizations are per client+scopes; selecting "any
        // authorization for the user" would incorrectly bind tokens issued for
        // one client to a different client.
        if (!string.IsNullOrEmpty(clientId))
        {
            var application = await _applicationManager.FindByClientIdAsync(clientId);
            if (application != null)
            {
                object? authorization = null;
                await foreach (var auth in _authorizationManager.FindAsync(
                    subject: user.Id,
                    client: await _applicationManager.GetIdAsync(application)!,
                    status: Statuses.Valid,
                    type: AuthorizationTypes.Permanent,
                    scopes: principal.GetScopes()))
                {
                    authorization = auth;
                    break;
                }

                authorization ??= await _authorizationManager.CreateAsync(
                    principal: principal,
                    subject: user.Id,
                    client: await _applicationManager.GetIdAsync(application)!,
                    type: AuthorizationTypes.Permanent,
                    scopes: principal.GetScopes());

                principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            }
        }

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        return principal;
    }

    /// <summary>
    /// Claims carry no destination by default; OpenIddict only serializes the
    /// ones explicitly routed to the access token, the identity token, or both.
    /// </summary>
    public static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        switch (claim.Type)
        {
            case Claims.Name:
            case Claims.Email:
            case Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Profile) || principal.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Tenant claim. Resource servers partition storage on it —
            // andy-ahp keys row-level security, cache namespaces, object keys
            // and quotas off `tid` — so it has to reach the access token, and
            // a client that displays which tenant it signed into reads the
            // identity token, so it reaches both. Stated explicitly rather
            // than left to the default arm so that removing it is a deliberate
            // edit.
            case DeploymentTenant.ClaimType:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                yield break;

            // Groups claim for RBAC integration - always include in access token
            case "groups":
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                yield break;

            // Permission claim for RBAC integration — access token only
            // (downstream service policies read it; it has no place in the
            // identity token, which is for the client/UI).
            case "permission":
                yield return Destinations.AccessToken;
                yield break;

            // Session identifier — access token only. SessionApiController
            // resolves session truth for a bearer token from this claim
            // (andy-auth#154); the identity token is for the client/UI and has
            // no use for it.
            case AndyAuthSignInManager.SessionIdClaimType:
                yield return Destinations.AccessToken;
                yield break;

            // Never include the security stamp in the access and identity
            // tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }

    private async Task<List<string>> GetUserGroupsAsync(string userId)
    {
        var now = DateTime.UtcNow;
        return await _dbContext.UserGroups
            .AsNoTracking()
            .Where(ug => ug.UserId == userId
                && ug.Group.IsActive
                && (ug.ExpiresAt == null || ug.ExpiresAt > now))
            .Select(ug => ug.Group.Code)
            .ToListAsync();
    }
}
