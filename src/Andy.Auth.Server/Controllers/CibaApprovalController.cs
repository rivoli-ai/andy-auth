using System.Security.Cryptography;
using System.Text.Json;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Andy.Auth.Server.Services.Ciba;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Controllers;

[Authorize(AuthenticationSchemes = "Identity.Application")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class CibaApprovalController(ApplicationDbContext db, IOptions<CibaOptions> options,
    IDataProtectionProvider protection, UserManager<ApplicationUser> users, SignInManager<ApplicationUser> signIn,
    SessionService sessions, IOpenIddictApplicationManager applications, TimeProvider clock) : Controller
{
    [HttpGet("~/Ciba/Device")]
    public async Task<IActionResult> Device()
    {
        if (!options.Value.Enabled) return NotFound();
        var user = await LiveUser();
        if (user == null) return Unauthorized();
        ViewBag.PublicKey = options.Value.VapidPublicKey;
        ViewBag.Registered = await db.CibaPushDevices.AnyAsync(row => row.UserId == user.Id);
        return View("Device");
    }

    [HttpPost("~/Ciba/Device")]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(16384)]
    public async Task<IActionResult> RegisterDevice(string endpoint, string p256dh, string auth, string password, string? code)
    {
        if (!options.Value.Enabled) return NotFound();
        var user = await LiveUser();
        if (user == null || !await FreshAuthentication(user, password, code)) return Unauthorized();
        if (string.IsNullOrEmpty(endpoint) || !options.Value.AllowsEndpoint(endpoint)) return BadRequest();
        try
        {
            var point = Base64UrlEncoder.DecodeBytes(p256dh);
            if (point.Length != 65 || point[0] != 4 || Base64UrlEncoder.DecodeBytes(auth).Length != 16) return BadRequest();
            using var ec = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = point[1..33], Y = point[33..65] } });
        }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException) { return BadRequest(); }
        var hash = CibaService.Hash(endpoint);
        if (await db.CibaPushDevices.AnyAsync(row => row.EndpointHash == hash && row.UserId != user.Id)) return Conflict();
        var device = await db.CibaPushDevices.SingleOrDefaultAsync(row => row.UserId == user.Id);
        if (device == null) { device = new CibaPushDevice { UserId = user.Id }; db.CibaPushDevices.Add(device); }
        device.EndpointHash = hash;
        device.ProtectedSubscription = protection.CreateProtector(CibaPushDelivery.ProtectionPurpose)
            .Protect(JsonSerializer.Serialize(new CibaSubscription(endpoint, p256dh, auth)));
        device.RegisteredAtUtc = clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(HttpContext.RequestAborted);
        return Ok(new { registered = true });
    }

    [HttpPost("~/Ciba/Device/Remove")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveDevice(string password, string? code)
    {
        if (!options.Value.Enabled) return NotFound();
        var user = await LiveUser();
        if (user == null || !await FreshAuthentication(user, password, code)) return Unauthorized();
        await db.CibaPushDevices.Where(row => row.UserId == user.Id).ExecuteDeleteAsync(HttpContext.RequestAborted);
        return RedirectToAction(nameof(Device));
    }

    [HttpGet("~/Ciba/Approve/{id}")]
    public async Task<IActionResult> Approve(string id)
    {
        if (!options.Value.Enabled) return NotFound();
        var user = await LiveUser();
        if (user == null) return Unauthorized();
        var row = await Pending(id, user.Id);
        if (row == null) return NotFound();
        var application = await applications.FindByClientIdAsync(row.ClientId);
        ViewBag.ClientName = application == null ? row.ClientId : await applications.GetDisplayNameAsync(application) ?? row.ClientId;
        ViewBag.RequiresMfa = await users.GetTwoFactorEnabledAsync(user);
        return View("Approve", row);
    }

    [HttpPost("~/Ciba/Approve/{id}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Decide(string id, string decision, string? password, string? code)
    {
        if (!options.Value.Enabled) return NotFound();
        var user = await LiveUser();
        if (user == null) return Unauthorized();
        if (decision is not ("allow" or "deny")) return BadRequest();
        var row = await Pending(id, user.Id);
        if (row == null) return NotFound();
        if (decision == "allow" && !await FreshAuthentication(user, password, code)) return Unauthorized();
        var now = clock.GetUtcNow().UtcDateTime;
        var session = User.GetClaim("session_id");
        var mfa = await users.GetTwoFactorEnabledAsync(user);
        var stamp = CibaService.Hash(await users.GetSecurityStampAsync(user));
        var changed = await db.CibaAuthentications.Where(item => item.Id == id && item.UserId == user.Id && item.Status == "pending" && item.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Status, decision == "allow" ? "approved" : "denied")
                .SetProperty(item => item.SessionId, session).SetProperty(item => item.ApprovedAtUtc, now)
                .SetProperty(item => item.UsedMfa, mfa).SetProperty(item => item.SecurityStampHash, stamp), HttpContext.RequestAborted);
        if (changed != 1) return Conflict();
        ViewBag.Approved = decision == "allow";
        return View("Complete");
    }

    private async Task<CibaAuthentication?> Pending(string id, string userId)
    {
        if (!Guid.TryParseExact(id, "N", out _)) return null;
        var now = clock.GetUtcNow().UtcDateTime;
        return await db.CibaAuthentications.AsNoTracking().SingleOrDefaultAsync(row => row.Id == id && row.UserId == userId &&
            row.Status == "pending" && row.ExpiresAtUtc > now, HttpContext.RequestAborted);
    }
    private async Task<ApplicationUser?> LiveUser()
    {
        var user = await users.GetUserAsync(User);
        return user != null && user.DeletedAt == null && await signIn.CanSignInAsync(user) && !await users.IsLockedOutAsync(user) &&
            await sessions.IsSessionValidForUserAsync(User.GetClaim("session_id"), user.Id) ? user : null;
    }
    private async Task<bool> FreshAuthentication(ApplicationUser user, string? password, string? code)
    {
        if (string.IsNullOrEmpty(password) || !(await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true)).Succeeded) return false;
        if (!await users.GetTwoFactorEnabledAsync(user)) return true;
        if (!string.IsNullOrWhiteSpace(code) && await users.VerifyTwoFactorTokenAsync(user,
            TokenOptions.DefaultAuthenticatorProvider, code.Replace(" ", "").Replace("-", ""))) return true;
        await users.AccessFailedAsync(user);
        return false;
    }
}
