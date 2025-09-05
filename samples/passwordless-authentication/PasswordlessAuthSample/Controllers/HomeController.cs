using Microsoft.AspNetCore.Mvc;

namespace PasswordlessAuthSample.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => View();
}