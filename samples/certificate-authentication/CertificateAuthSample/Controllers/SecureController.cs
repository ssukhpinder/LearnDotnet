using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CertificateAuthSample.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize]
public class SecureController : ControllerBase
{
    [HttpGet("data")]
    public IActionResult GetSecureData()
    {
        return Ok(new { 
            message = "This is protected data accessed via certificate authentication",
            subject = User.Identity?.Name,
            timestamp = DateTime.UtcNow
        });
    }
}