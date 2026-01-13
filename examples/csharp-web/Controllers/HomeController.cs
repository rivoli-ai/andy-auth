using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CSharpWebExample.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [Authorize]
    public IActionResult Secure()
    {
        return View();
    }

    public IActionResult Error(string? message)
    {
        ViewBag.ErrorMessage = message ?? "An unknown error occurred";
        return View();
    }
}
