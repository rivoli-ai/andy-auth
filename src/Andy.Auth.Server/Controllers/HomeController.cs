using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Andy.Auth.Server.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        // Redirect authenticated users based on their role
        if (User.Identity?.IsAuthenticated == true)
        {
            if (User.IsInRole("Admin"))
            {
                return RedirectToAction("Index", "Admin");
            }
            else
            {
                // Non-admin users get a simple success page
                return View("UserSuccess");
            }
        }

        // Non-authenticated users see the home page
        return View();
    }

    [Authorize(AuthenticationSchemes = "Identity.Application")]
    public IActionResult UserSuccess()
    {
        // Simple page for authenticated non-admin users
        return View();
    }

    public IActionResult Error()
    {
        return View();
    }

    public IActionResult AccessDenied()
    {
        // Show access denied page for unauthorized users
        return View();
    }
}
