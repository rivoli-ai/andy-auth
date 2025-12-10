using Andy.Auth.Server.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Controllers;

[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _dbContext;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext dbContext)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _dbContext = dbContext;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        // If the user is not authenticated, redirect them to the login page
        if (!result.Succeeded)
        {
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // Retrieve the profile of the logged in user
        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details from the database
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application
        var authorizations = new List<object>();
        await foreach (var authorization in _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application)!,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()))
        {
            authorizations.Add(authorization);
        }

        // Check if the user has already granted consent for this client and scopes
        var userId = await _userManager.GetUserIdAsync(user);
        var requestedScopes = request.GetScopes().ToList();
        var existingConsent = await _dbContext.UserConsents
            .FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == request.ClientId);

        // Check if consent was just granted (redirect from consent page)
        var consentGranted = Request.Query.ContainsKey("consent_granted") &&
                             Request.Query["consent_granted"] == "true";

        var hasValidConsent = existingConsent != null &&
                              existingConsent.IsValid &&
                              existingConsent.CoversScopes(requestedScopes);

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            // If the consent is external (e.g., when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database
            case ConsentTypes.External when !authorizations.Any():
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
                var principal = await CreateClaimsPrincipalAsync(user, request.GetScopes());

                // Always include lexipro-api audience for wagram-web client
                if (request.ClientId == "wagram-web")
                {
                    var currentResources = principal.GetResources().ToList();
                    const string lexiproApiResource = "urn:lexipro-api";
                    if (!currentResources.Contains(lexiproApiResource))
                    {
                        currentResources.Add(lexiproApiResource);
                    }
                    principal.SetResources(currentResources);
                }

                // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code
                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // For explicit consent, check if user has already granted consent
            case ConsentTypes.Explicit when authorizations.Any():
            case ConsentTypes.Explicit when hasValidConsent:
            case ConsentTypes.Explicit when consentGranted:
                var principalExplicit = await CreateClaimsPrincipalAsync(user, request.GetScopes());

                // Always include lexipro-api audience for wagram-web client
                if (request.ClientId == "wagram-web")
                {
                    var currentResources = principalExplicit.GetResources().ToList();
                    const string lexiproApiResource = "urn:lexipro-api";
                    if (!currentResources.Contains(lexiproApiResource))
                    {
                        currentResources.Add(lexiproApiResource);
                    }
                    principalExplicit.SetResources(currentResources);
                }

                return SignIn(principalExplicit, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // For explicit/systematic consent without prior consent, redirect to consent page
            // unless prompt=none was specified
            case ConsentTypes.Explicit:
            case ConsentTypes.Systematic:
                // If prompt=none, return error as we can't show consent UI
                if (request.Prompt == "none")
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "Interactive user consent is required."
                        }));
                }

                // Redirect to consent page
                var returnUrl = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList());
                return Redirect($"/Consent?returnUrl={Uri.EscapeDataString(returnUrl)}");

            // Default case: check for existing consent or redirect to consent page
            default:
                // If user has valid consent, proceed
                if (hasValidConsent || consentGranted)
                {
                    var principalDefault = await CreateClaimsPrincipalAsync(user, request.GetScopes());
                    return SignIn(principalDefault, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                // Redirect to consent page
                var defaultReturnUrl = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList());
                return Redirect($"/Consent?returnUrl={Uri.EscapeDataString(defaultReturnUrl)}");
        }
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the authorization code/refresh token
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Retrieve the user profile corresponding to the authorization code/refresh token
            var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject)!);
            if (user == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            // Ensure the user is still allowed to sign in
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            var principal = await CreateClaimsPrincipalAsync(user, result.Principal.GetScopes());

            // Handle resource parameter (RFC 8707 - MCP requirement)
            var requestedResources = request.GetResources();
            if (requestedResources.Any())
            {
                // Explicit resource parameter provided - use those resources
                principal.SetResources(requestedResources);
            }

            // Always include lexipro-api audience for wagram-web client
            if (request.ClientId == "wagram-web")
            {
                var currentResources = principal.GetResources().ToList();
                const string lexiproApiResource = "urn:lexipro-api";
                if (!currentResources.Contains(lexiproApiResource))
                {
                    currentResources.Add(lexiproApiResource);
                }
                principal.SetResources(currentResources);
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (request.IsClientCredentialsGrantType())
        {
            // Note: the client credentials are automatically validated by OpenIddict:
            // if client_id or client_secret are invalid, this action won't be invoked
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
                throw new InvalidOperationException("The application details cannot be found in the database.");

            // Create a new ClaimsIdentity containing the claims that will be used to create an id_token, a token or a code
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Use the client_id as the subject identifier
            identity.AddClaim(new Claim(Claims.Subject, await _applicationManager.GetClientIdAsync(application)!)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            identity.AddClaim(new Claim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application)!)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            // Set resources from explicit resource parameter (RFC 8707) or from scopes
            var resources = new List<string>();

            // First, check if explicit resource parameter was provided (RFC 8707 - MCP requirement)
            var requestedResources = request.GetResources();
            if (requestedResources.Any())
            {
                resources.AddRange(requestedResources);
            }
            else
            {
                // Fallback: Get resources associated with requested scopes
                await foreach (var resource in _scopeManager.ListResourcesAsync(principal.GetScopes()))
                {
                    resources.Add(resource);
                }
            }

            principal.SetResources(resources);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.FindByIdAsync(User.GetClaim(Claims.Subject)!);
        if (user == null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response
            [Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await _userManager.GetEmailAsync(user) ?? string.Empty;
            claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.FullName ?? string.Empty;
            claims[Claims.PreferredUsername] = await _userManager.GetUserNameAsync(user) ?? string.Empty;
            claims["profile_picture_url"] = user.ProfilePictureUrl ?? string.Empty;
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        // Note: the complete list of standard claims supported by the OpenID Connect specification
        // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

        return Ok(claims);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        // Ask OpenIddict to sign the user out
        await _signInManager.SignOutAsync();

        // Retrieve the logout request and post_logout_redirect_uri
        var request = HttpContext.GetOpenIddictServerRequest();

        if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUri))
        {
            // Redirect the user to the post_logout_redirect_uri
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = request.PostLogoutRedirectUri
                });
        }

        // If no post_logout_redirect_uri was specified, redirect to home
        return Redirect("/");
    }

    private async Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ApplicationUser user, IEnumerable<string> scopes)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        var identity = (ClaimsIdentity)principal.Identity!;

        // Add the claims that will be persisted in the tokens
        identity.AddClaim(new Claim(Claims.Subject, user.Id).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.Email, user.Email!).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.Name, user.FullName ?? user.UserName ?? user.Email!).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
        identity.AddClaim(new Claim(Claims.PreferredUsername, user.UserName ?? user.Email!).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

        // Set the list of scopes granted to the client application
        principal.SetScopes(scopes);

        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(principal.GetScopes()))
        {
            resources.Add(resource);
        }
        principal.SetResources(resources);

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes
        object? authorization = null;
        await foreach (var auth in _authorizationManager.FindBySubjectAsync(user.Id))
        {
            authorization = auth;
            break;
        }
        if (authorization == null)
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            var application = await _applicationManager.FindByClientIdAsync(request!.ClientId!);

            authorization = await _authorizationManager.CreateAsync(
                principal: principal,
                subject: user.Id,
                client: await _applicationManager.GetIdAsync(application!)!,
                type: AuthorizationTypes.Permanent,
                scopes: principal.GetScopes());
        }

        principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        return principal;
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

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

            // Never include the security stamp in the access and identity tokens, as it's a secret value
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
