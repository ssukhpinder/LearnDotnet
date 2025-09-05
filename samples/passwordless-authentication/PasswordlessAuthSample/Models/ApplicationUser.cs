using Microsoft.AspNetCore.Identity;

namespace PasswordlessAuthSample.Models;

public class ApplicationUser : IdentityUser
{
    public DateTime? LastLoginTime { get; set; }
}