using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using QRCoder;
using System.Text;
using System.Text.Encodings.Web;
using TwoFactorAuthSample.Models;

namespace TwoFactorAuthSample.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
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
            return RedirectToAction("Setup2FA");
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
        var result = await _signInManager.PasswordSignInAsync(email, password, false, false);
        
        if (result.RequiresTwoFactor)
            return RedirectToAction("Verify2FA");
        
        if (result.Succeeded)
            return RedirectToAction("Index", "Home");
        
        ModelState.AddModelError("", "Invalid login attempt");
        return View();
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Setup2FA()
    {
        var user = await _userManager.GetUserAsync(User);
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var qrCodeUri = GenerateQrCodeUri(user.Email!, key);
        ViewBag.QrCodeUri = qrCodeUri;
        ViewBag.ManualEntryKey = FormatKey(key);
        
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Enable2FA(string code)
    {
        var user = await _userManager.GetUserAsync(User);
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);
        
        if (isValid)
        {
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction("Index", "Home");
        }
        
        ModelState.AddModelError("", "Invalid verification code");
        return RedirectToAction("Setup2FA");
    }

    [HttpGet]
    public IActionResult Verify2FA() => View();

    [HttpPost]
    public async Task<IActionResult> Verify2FA(string code)
    {
        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, false, false);
        
        if (result.Succeeded)
            return RedirectToAction("Index", "Home");
        
        ModelState.AddModelError("", "Invalid verification code");
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    private string GenerateQrCodeUri(string email, string key)
    {
        return $"otpauth://totp/TwoFactorAuthSample:{UrlEncoder.Default.Encode(email)}?secret={key}&issuer=TwoFactorAuthSample";
    }

    private string FormatKey(string key)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < key.Length)
        {
            result.Append(key.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < key.Length)
            result.Append(key.AsSpan(currentPosition));

        return result.ToString().ToLowerInvariant();
    }
}