using Microsoft.AspNetCore.Mvc;

namespace CertificateAuthSample.Controllers;

[ApiController]
[Route("[controller]")]
public class PublicController : ControllerBase
{
    [HttpGet("info")]
    public IActionResult GetInfo()
    {
        return Ok(new { 
            message = "This is public data - no certificate required",
            timestamp = DateTime.UtcNow
        });
    }
}