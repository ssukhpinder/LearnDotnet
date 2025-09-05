using Microsoft.AspNetCore.Authorization;

namespace PolicyAuthSample.Authorization;

public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    
    public MinimumAgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }
}

public class DepartmentRequirement : IAuthorizationRequirement
{
    public string[] AllowedDepartments { get; }
    
    public DepartmentRequirement(params string[] allowedDepartments)
    {
        AllowedDepartments = allowedDepartments;
    }
}

public class ResourceOwnerRequirement : IAuthorizationRequirement
{
}

public class BusinessHoursRequirement : IAuthorizationRequirement
{
    public TimeSpan StartTime { get; }
    public TimeSpan EndTime { get; }
    
    public BusinessHoursRequirement(TimeSpan startTime, TimeSpan endTime)
    {
        StartTime = startTime;
        EndTime = endTime;
    }
}