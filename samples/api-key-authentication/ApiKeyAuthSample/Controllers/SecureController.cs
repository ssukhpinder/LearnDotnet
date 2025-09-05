using Microsoft.AspNetCore.Mvc;

namespace ApiKeyAuthSample.Controllers;

[ApiController]
[Route("[controller]")]
public class SecureController : ControllerBase
{
    [HttpGet("data")]
    public IActionResult GetSecureData()
    {
        return Ok(new { 
            message = "This is protected data accessed with API key",
            timestamp = DateTime.UtcNow
        });
    }
}