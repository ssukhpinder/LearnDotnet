using Microsoft.AspNetCore.Mvc;

namespace TwoFactorAuthSample.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}