using System.Globalization;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Andy.Auth.Server.Services.Ciba;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Andy.Auth.Server.Controllers;

public sealed class CibaController(IOptions<CibaOptions> options, ApplicationDbContext db,
    IOpenIddictServerFactory transactions, IOpenIddictServerDispatcher dispatcher,
    IOpenIddictApplicationManager applications, IOpenIddictScopeManager scopes,
    IOptionsMonitor<OpenIddictServerOptions> server, DcrClientGate gate, UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn, IServiceProvider services, ILogger<CibaController> logger) : Controller
{
    [HttpPost("~/connect/bc-authorize")]
    [RequestSizeLimit(16384)]
    public async Task<IActionResult> Start()
    {
        if (!options.Value.Enabled) return NotFound();
        Response.Headers.CacheControl = "no-store";
        if (!Request.IsHttps || !Request.HasFormContentType) return Error("invalid_request");
        try
        {
            var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
            if (form.Any(pair => pair.Value.Count != 1)) return Error("invalid_request");
            // Reuse native backchannel form extraction and client authentication,
            // without invoking PAR validation, storage or authorization handling.
            var transaction = await transactions.CreateTransactionAsync();
            transaction.EndpointType = OpenIddictServerEndpointType.PushedAuthorization;
            transaction.BaseUri = new Uri(Request.Scheme + "://" + Request.Host + Request.PathBase + "/");
            transaction.RequestUri = new Uri(Request.GetEncodedUrl());
            transaction.Properties[typeof(HttpRequest).FullName!] = new WeakReference<HttpRequest>(Request);
            var extraction = new ExtractPushedAuthorizationRequestContext(transaction);
            await dispatcher.DispatchAsync(extraction);
            if (extraction.IsRejected || extraction.Request == null) return Error(extraction.Error ?? "invalid_request");
            var authentication = new ProcessAuthenticationContext(transaction);
            await dispatcher.DispatchAsync(authentication);
            if (authentication.IsRejected) return Error(authentication.Error ?? "invalid_client");
            var request = extraction.Request;
            var clientId = authentication.ClientId ?? request.ClientId;
            var application = clientId == null ? null : await applications.FindByClientIdAsync(clientId);
            if (application == null || await applications.HasClientTypeAsync(application, OpenIddictConstants.ClientTypes.Public) ||
                await gate.GetDenialReasonAsync(clientId!) != null) return Error("invalid_client");
            var properties = await applications.GetPropertiesAsync(application);
            if (!await applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.Endpoints.Token) ||
                !await applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.Prefixes.GrantType + CibaOptions.GrantType) ||
                !properties.TryGetValue(CibaOptions.DeliveryModeProperty, out var delivery) || delivery.GetString() != "poll")
                return Error("unauthorized_client");
            if (new[] { "request", "request_uri", "nonce", "login_hint_token", "id_token_hint", "user_code", "client_notification_token", "acr_values" }
                .Any(name => request.HasParameter(name))) return Error("invalid_request");
            var hint = (string?)request["login_hint"];
            if (string.IsNullOrWhiteSpace(hint) || hint.Length > 256 || hint.Any(char.IsControl)) return Error("invalid_request");
            var binding = (string?)request["binding_message"] ?? "";
            if (binding.Length > 128 || binding.Any(character => character < 32 || character > 126)) return Error("invalid_binding_message");
            var requested = request.GetScopes();
            if (!requested.Contains("openid") || request.Scope!.Length > 2048) return Error("invalid_scope");
            foreach (var scope in requested)
            {
                if (scope is "openid" or "offline_access") continue;
                if (!await applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.Prefixes.Scope + scope) ||
                    !server.CurrentValue.Scopes.Contains(scope) && await scopes.FindByNameAsync(scope) == null) return Error("invalid_scope");
            }
            if (requested.Contains("offline_access") && !await applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.GrantTypes.RefreshToken))
                return Error("invalid_scope");
            int? expiry = null;
            if (request.HasParameter("requested_expiry"))
            {
                if (!int.TryParse((string?)request["requested_expiry"], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) || seconds <= 0)
                    return Error("invalid_request");
                expiry = seconds;
            }
            ApplicationUser? user;
            if (hint.Contains('@'))
            {
                user = await users.FindByEmailAsync(hint);
                if (user?.EmailConfirmed != true) return Error("unknown_user_id");
            }
            else if (Regex.IsMatch(hint, "^\\+[1-9][0-9]{7,14}$"))
            {
                var matches = await db.Users.Where(row => row.PhoneNumber == hint && row.PhoneNumberConfirmed).Take(2).ToListAsync(HttpContext.RequestAborted);
                user = matches.Count == 1 ? matches[0] : null;
            }
            else return Error("unknown_user_id");
            if (user == null || user.DeletedAt != null || !await signIn.CanSignInAsync(user) || await users.IsLockedOutAsync(user) ||
                !await db.CibaPushDevices.AnyAsync(row => row.UserId == user.Id, HttpContext.RequestAborted)) return Error("unknown_user_id");
            var opaque = await services.GetRequiredService<CibaService>().StartAsync(user.Id, clientId!, request.Scope!, binding, expiry, HttpContext.RequestAborted);
            if (opaque == null) { Response.Headers.RetryAfter = "30"; return StatusCode(429, new { error = "slow_down" }); }
            return Ok(new { auth_req_id = opaque,
                expires_in = (int)Math.Min(expiry ?? int.MaxValue, options.Value.AuthenticationLifetime.TotalSeconds),
                interval = (int)options.Value.PollingInterval.TotalSeconds });
        }
        catch (Exception error)
        {
            logger.LogError("CIBA request authority unavailable ({FailureType})", error.GetType().Name);
            Response.Headers.RetryAfter = "5";
            return StatusCode(503, new { error = "temporarily_unavailable" });
        }
    }
    private IActionResult Error(string error)
    {
        if (error == "invalid_client" && Request.Headers.Authorization.ToString().StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"CIBA\"";
            return StatusCode(401, new { error });
        }
        return BadRequest(new { error });
    }
}
