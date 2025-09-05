using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ClaimsAuthSample.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ClaimsController : ControllerBase
{
    [HttpGet("my-claims")]
    public IActionResult GetMyClaims()
    {
        var claims = User.Claims.Select(c => new { c.Type, c.Value });
        return Ok(new { claims });
    }

    [HttpGet("check-claim/{claimType}/{claimValue}")]
    public IActionResult CheckClaim(string claimType, string claimValue)
    {
        var hasClaim = User.HasClaim(claimType, claimValue);
        return Ok(new { hasClaim, claimType, claimValue });
    }

    [HttpGet("department-data")]
    [Authorize(Policy = "DepartmentAccess")]
    public IActionResult GetDepartmentData()
    {
        var department = User.FindFirst("department")?.Value ?? "Unknown";
        return Ok(new { message = $"Department data for {department}", department });
    }
}