using Microsoft.AspNetCore.Mvc;

namespace BiometricAuthSample.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => View();
}