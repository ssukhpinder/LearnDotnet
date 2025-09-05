using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthSample.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize]
public class SecureController : ControllerBase
{
    [HttpGet("data")]
    public IActionResult GetSecureData()
    {
        return Ok(new { 
            message = "This is protected data",
            user = User.Identity?.Name,
            timestamp = DateTime.UtcNow
        });
    }
}