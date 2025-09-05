using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Principal;
using System.Runtime.Versioning;

namespace WindowsAuthSample.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize]
public class SecureController : ControllerBase
{
    [HttpGet("user-info")]
    [SupportedOSPlatform("windows")]
    public IActionResult GetUserInfo()
    {
        var windowsIdentity = User.Identity as WindowsIdentity;
        
        return Ok(new { 
            username = User.Identity?.Name,
            authenticationType = User.Identity?.AuthenticationType,
            isAuthenticated = User.Identity?.IsAuthenticated,
            groups = windowsIdentity?.Groups?.Select(g => g.Translate(typeof(NTAccount)).Value).ToArray(),
            timestamp = DateTime.UtcNow
        });
    }
}