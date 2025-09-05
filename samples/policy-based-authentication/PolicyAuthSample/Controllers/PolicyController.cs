using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolicyAuthSample.Authorization;
using System.Security.Claims;

namespace PolicyAuthSample.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class PolicyController : ControllerBase
{
    private readonly IAuthorizationService _authorizationService;

    public PolicyController(IAuthorizationService authorizationService)
    {
        _authorizationService = authorizationService;
    }

    [HttpGet("check-policy/{policyName}")]
    public async Task<IActionResult> CheckPolicy(string policyName)
    {
        var result = await _authorizationService.AuthorizeAsync(User, policyName);
        return Ok(new { policy = policyName, authorized = result.Succeeded });
    }

    [HttpGet("check-requirement")]
    public async Task<IActionResult> CheckRequirement(int minimumAge)
    {
        var requirement = new MinimumAgeRequirement(minimumAge);
        var result = await _authorizationService.AuthorizeAsync(User, null, requirement);
        return Ok(new { minimumAge, authorized = result.Succeeded });
    }

    [HttpGet("department-check")]
    public async Task<IActionResult> CheckDepartment([FromQuery] string[] departments)
    {
        var requirement = new DepartmentRequirement(departments);
        var result = await _authorizationService.AuthorizeAsync(User, null, requirement);
        return Ok(new { departments, authorized = result.Succeeded });
    }

    [HttpGet("business-hours")]
    public async Task<IActionResult> CheckBusinessHours()
    {
        var requirement = new BusinessHoursRequirement(new TimeSpan(9, 0, 0), new TimeSpan(17, 0, 0));
        var result = await _authorizationService.AuthorizeAsync(User, null, requirement);
        return Ok(new 
        { 
            currentTime = DateTime.Now.TimeOfDay,
            businessHours = "09:00 - 17:00",
            authorized = result.Succeeded 
        });
    }

    [HttpGet("resource-access/{resourceOwnerId}")]
    public async Task<IActionResult> CheckResourceAccess(string resourceOwnerId)
    {
        var result = await _authorizationService.AuthorizeAsync(User, resourceOwnerId, "ResourceOwner");
        return Ok(new { resourceOwnerId, authorized = result.Succeeded });
    }
}