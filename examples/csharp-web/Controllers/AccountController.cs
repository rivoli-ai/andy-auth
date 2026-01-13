using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CSharpWebExample.Controllers;

[Route("[controller]")]
public class AccountController : Controller
{
    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var redirectUrl = Url.Action("Index", "Home");
        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            redirectUrl = returnUrl;
        }

        return Challenge(new AuthenticationProperties
        {
            RedirectUri = redirectUrl
        }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

        return RedirectToAction("Index", "Home");
    }

    [HttpGet("profile")]
    [Authorize]
    public IActionResult Profile()
    {
        var claims = User.Claims.Select(c => new { c.Type, c.Value });
        return Json(claims);
    }

    [HttpGet("tokens")]
    [Authorize]
    public async Task<IActionResult> Tokens()
    {
        var accessToken = await HttpContext.GetTokenAsync("access_token");
        var idToken = await HttpContext.GetTokenAsync("id_token");
        var refreshToken = await HttpContext.GetTokenAsync("refresh_token");

        return Json(new
        {
            AccessToken = accessToken,
            IdToken = idToken,
            RefreshToken = refreshToken
        });
    }
}
