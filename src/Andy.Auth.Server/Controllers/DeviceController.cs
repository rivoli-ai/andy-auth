using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Controllers;

/// <summary>
/// User-facing endpoints for the RFC 8628 device authorization grant.
/// The CLI (or other headless client) starts the flow at
/// <c>/connect/device</c> (handled natively by OpenIddict) and shows
/// the user a <c>verification_uri</c> + <c>user_code</c>; the user
/// opens that URL in a browser, signs in, lands here, and authorizes
/// the request. OpenIddict associates the resulting principal with
/// the device_code so the polling client can complete the flow at
/// <c>/connect/token</c>.
/// </summary>
[Authorize(AuthenticationSchemes = "Identity.Application")]
public class DeviceController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<DeviceController> _logger;

    public DeviceController(
        IOpenIddictApplicationManager applicationManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        ApplicationDbContext dbContext,
        ILogger<DeviceController> logger)
    {
        _applicationManager = applicationManager;
        _userManager = userManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _dbContext = dbContext;
        _logger = logger;
    }

    /// <summary>
    /// GET /connect/verify — renders the code-entry form, or jumps
    /// straight to the consent screen when the user_code is already
    /// present in the request (the CLI typically prints a
    /// verification_uri_complete that includes <c>?user_code=…</c>).
    /// </summary>
    [HttpGet("~/connect/verify")]
    public async Task<IActionResult> Verify()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // No user_code: show the entry form. The form posts back here
        // with the user_code in the request body, which OpenIddict
        // picks up to resolve the device_code.
        if (string.IsNullOrEmpty(request.UserCode))
        {
            return View("Verify", new DeviceVerifyViewModel());
        }

        // user_code provided: ask OpenIddict to resolve it. A failure
        // means the code is unknown, expired, or already redeemed.
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result.Principal is null || !result.Succeeded)
        {
            return View("Verify", new DeviceVerifyViewModel
            {
                UserCode = request.UserCode,
                Error = "The code you entered is invalid or has expired. Try again with a freshly issued code."
            });
        }

        var clientId = result.Principal.GetClaim(Claims.ClientId);
        var application = string.IsNullOrEmpty(clientId)
            ? null
            : await _applicationManager.FindByClientIdAsync(clientId);
        var clientName = application is null
            ? clientId ?? "the application"
            : (await _applicationManager.GetDisplayNameAsync(application)) ?? clientId ?? "the application";

        return View("VerifyConsent", new DeviceVerifyConsentViewModel
        {
            UserCode = request.UserCode,
            ClientName = clientName,
            Scopes = result.Principal.GetScopes().ToList(),
        });
    }

    /// <summary>
    /// POST /connect/verify — user accepts (allow) or rejects (deny)
    /// the device-authorization request. Allow signs in with the
    /// user's claims under the OpenIddict scheme so the principal gets
    /// stored against the device_code for the polling client to pick
    /// up. Deny rejects the request; the polling client will see
    /// <c>access_denied</c> on its next /connect/token poll.
    /// </summary>
    [HttpPost("~/connect/verify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAccept(string userCode, string decision)
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result.Principal is null || !result.Succeeded)
        {
            return View("Verify", new DeviceVerifyViewModel
            {
                UserCode = userCode,
                Error = "The code you entered is invalid or has expired."
            });
        }

        if (string.Equals(decision, "deny", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("Device authorization denied by user for user_code {UserCode}", userCode);
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user denied the device-authorization request."
                }));
        }

        var user = await _userManager.GetUserAsync(User) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        var principal = await CreateClaimsPrincipalAsync(user, result.Principal.GetScopes(), result.Principal.GetClaim(Claims.ClientId));

        _logger.LogInformation(
            "Device authorization granted: user {UserId}, client {ClientId}, scopes {Scopes}",
            user.Id,
            result.Principal.GetClaim(Claims.ClientId),
            string.Join(" ", principal.GetScopes()));

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Mirrors AuthorizationController.CreateClaimsPrincipalAsync but
    /// with the client_id passed in explicitly (the OpenIddict server
    /// request at the verification endpoint doesn't carry it the same
    /// way the auth-code flow does — it's instead part of the
    /// device-authorization principal returned by AuthenticateAsync).
    /// Kept as a private copy rather than refactoring the shared
    /// implementation to avoid disturbing the existing auth-code flow
    /// in this PR.
    /// </summary>
    private async Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ApplicationUser user, IEnumerable<string> scopes, string? clientId)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        var identity = (ClaimsIdentity)principal.Identity!;

        identity.AddClaim(new Claim(Claims.Subject, user.Id).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.Email, user.Email!).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.Name, user.FullName ?? user.UserName ?? user.Email!).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.PreferredUsername, user.UserName ?? user.Email!).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

        var groups = await _dbContext.UserGroups
            .AsNoTracking()
            .Where(ug => ug.UserId == user.Id && ug.Group.IsActive && (ug.ExpiresAt == null || ug.ExpiresAt > DateTime.UtcNow))
            .Select(ug => ug.Group.Code)
            .ToListAsync();
        foreach (var groupCode in groups)
        {
            identity.AddClaim(new Claim("groups", groupCode).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        }

        principal.SetScopes(scopes);

        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(principal.GetScopes()))
        {
            resources.Add(resource);
        }
        principal.SetResources(resources);

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

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal) => claim.Type switch
    {
        Claims.Name or Claims.Email or Claims.PreferredUsername => principal.HasScope(Scopes.Profile) || principal.HasScope(Scopes.Email)
            ? new[] { Destinations.AccessToken, Destinations.IdentityToken }
            : new[] { Destinations.AccessToken },
        Claims.Role => principal.HasScope(Scopes.Roles)
            ? new[] { Destinations.AccessToken, Destinations.IdentityToken }
            : new[] { Destinations.AccessToken },
        "groups" => new[] { Destinations.AccessToken, Destinations.IdentityToken },
        "AspNet.Identity.SecurityStamp" => Array.Empty<string>(),
        _ => new[] { Destinations.AccessToken },
    };
}
