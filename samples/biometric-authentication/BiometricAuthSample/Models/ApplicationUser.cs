using Microsoft.AspNetCore.Identity;

namespace BiometricAuthSample.Models;

public class ApplicationUser : IdentityUser
{
    public bool BiometricEnabled { get; set; }
    public string? BiometricCredentialId { get; set; }
    public string? BiometricPublicKey { get; set; }
}