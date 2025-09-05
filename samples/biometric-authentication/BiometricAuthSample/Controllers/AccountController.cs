using BiometricAuthSample.Models;
using BiometricAuthSample.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace BiometricAuthSample.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IBiometricService _biometricService;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IBiometricService biometricService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _biometricService = biometricService;
    }

    [HttpGet]
    public IActionResult Register() => View();

    [HttpPost]
    public async Task<IActionResult> Register(string email, string password)
    {
        var user = new ApplicationUser { UserName = email, Email = email };
        var result = await _userManager.CreateAsync(user, password);
        
        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction("SetupBiometric");
        }
        
        foreach (var error in result.Errors)
            ModelState.AddModelError("", error.Description);
        
        return View();
    }

    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    public async Task<IActionResult> Login(string email, string password)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user?.BiometricEnabled == true)
        {
            var challenge = await _biometricService.GenerateChallenge();
            TempData["Challenge"] = challenge;
            TempData["UserId"] = user.Id;
            return RedirectToAction("BiometricLogin");
        }

        var result = await _signInManager.PasswordSignInAsync(email, password, false, false);
        if (result.Succeeded)
            return RedirectToAction("Index", "Home");
        
        ModelState.AddModelError("", "Invalid login attempt");
        return View();
    }

    [HttpGet]
    public IActionResult BiometricLogin()
    {
        ViewBag.Challenge = TempData["Challenge"];
        ViewBag.UserId = TempData["UserId"];
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> BiometricLogin(string credentialId, string signature, string challenge)
    {
        var isValid = await _biometricService.VerifyBiometric(credentialId, signature, challenge);
        
        if (isValid)
        {
            var user = await _userManager.FindByIdAsync(TempData["UserId"]?.ToString() ?? "");
            if (user != null)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }
        }
        
        ModelState.AddModelError("", "Biometric authentication failed");
        return View();
    }

    [Authorize]
    [HttpGet]
    public IActionResult SetupBiometric() => View();

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> SetupBiometric(string publicKey)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user != null)
        {
            var credential = await _biometricService.RegisterBiometric(user.Id, publicKey);
            user.BiometricEnabled = true;
            user.BiometricCredentialId = credential.Id;
            user.BiometricPublicKey = publicKey;
            
            await _userManager.UpdateAsync(user);
            return RedirectToAction("Index", "Home");
        }
        
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public IActionResult SimulateBiometric(string challenge)
    {
        // Simulate biometric signature generation
        var publicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var signature = Convert.ToBase64String(
            SHA256.HashData(Encoding.UTF8.GetBytes(challenge + publicKey)));
        
        return Json(new { publicKey, signature });
    }
}