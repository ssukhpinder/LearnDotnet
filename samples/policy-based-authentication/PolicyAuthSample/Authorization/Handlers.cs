using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace PolicyAuthSample.Authorization;

public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var ageClaim = context.User.FindFirst("age");
        if (ageClaim != null && int.TryParse(ageClaim.Value, out int age))
        {
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }
        
        return Task.CompletedTask;
    }
}

public class DepartmentHandler : AuthorizationHandler<DepartmentRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DepartmentRequirement requirement)
    {
        var departmentClaim = context.User.FindFirst("department");
        if (departmentClaim != null && 
            requirement.AllowedDepartments.Contains(departmentClaim.Value, StringComparer.OrdinalIgnoreCase))
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}

public class ResourceOwnerHandler : AuthorizationHandler<ResourceOwnerRequirement, string>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ResourceOwnerRequirement requirement,
        string resourceOwnerId)
    {
        var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier);
        if (userIdClaim != null && userIdClaim.Value == resourceOwnerId)
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}

public class BusinessHoursHandler : AuthorizationHandler<BusinessHoursRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        BusinessHoursRequirement requirement)
    {
        var currentTime = DateTime.Now.TimeOfDay;
        
        if (currentTime >= requirement.StartTime && currentTime <= requirement.EndTime)
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}