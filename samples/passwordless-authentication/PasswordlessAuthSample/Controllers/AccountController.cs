using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PasswordlessAuthSample.Models;
using PasswordlessAuthSample.Services;

namespace PasswordlessAuthSample.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailService _emailService;
    private readonly IMagicLinkService _magicLinkService;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IEmailService emailService,
        IMagicLinkService magicLinkService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailService = emailService;
        _magicLinkService = magicLinkService;
    }

    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    public async Task<IActionResult> Login(string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            ModelState.AddModelError("", "Email is required");
            return View();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            user = new ApplicationUser { UserName = email, Email = email };
            await _userManager.CreateAsync(user);
        }

        var token = _magicLinkService.GenerateMagicLink(email);
        var magicLink = Url.Action("VerifyMagicLink", "Account", new { token }, Request.Scheme);
        
        await _emailService.SendMagicLinkAsync(email, magicLink!);
        
        return View("LinkSent");
    }

    [HttpGet]
    public async Task<IActionResult> VerifyMagicLink(string token)
    {
        if (_magicLinkService.ValidateMagicLink(token, out string email))
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                user.LastLoginTime = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }
        }
        
        return View("InvalidLink");
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }
}