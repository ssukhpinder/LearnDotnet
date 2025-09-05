using Microsoft.AspNetCore.Identity;

namespace TwoFactorAuthSample.Models;

public class ApplicationUser : IdentityUser
{
    public bool TwoFactorEnabled { get; set; }
}