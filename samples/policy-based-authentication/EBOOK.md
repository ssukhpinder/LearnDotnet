# Policy-Based Authentication in ASP.NET Core: A Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding Policy-Based Authorization](#understanding-policy-based-authorization)
3. [Authorization Requirements](#authorization-requirements)
4. [Authorization Handlers](#authorization-handlers)
5. [Policy Configuration](#policy-configuration)
6. [Resource-Based Authorization](#resource-based-authorization)
7. [Advanced Scenarios](#advanced-scenarios)
8. [Best Practices](#best-practices)
9. [Performance Considerations](#performance-considerations)
10. [Testing Strategies](#testing-strategies)
11. [Troubleshooting](#troubleshooting)
12. [Conclusion](#conclusion)

## Introduction

Policy-based authorization in ASP.NET Core represents the most flexible and powerful approach to securing applications. Unlike simple role-based or claims-based authorization, policy-based authorization allows you to create complex business rules that can evaluate multiple factors to make authorization decisions.

This approach separates authorization logic from your controllers and actions, making your code more maintainable, testable, and reusable. It enables you to implement sophisticated authorization scenarios that reflect real-world business requirements.

## Understanding Policy-Based Authorization

### The Authorization Pipeline

When a request hits an authorized endpoint, ASP.NET Core follows this process:

1. **Authentication**: Verify the user's identity
2. **Authorization**: Check if the authenticated user has permission
3. **Policy Evaluation**: Run custom requirements and handlers
4. **Decision**: Allow or deny access

### Core Components

#### 1. Requirements (IAuthorizationRequirement)
Requirements define what needs to be checked. They are simple marker interfaces that contain the criteria for authorization.

```csharp
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    
    public MinimumAgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }
}
```

#### 2. Handlers (AuthorizationHandler<T>)
Handlers contain the logic that evaluates requirements. They determine whether a requirement is satisfied.

```csharp
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
```

#### 3. Policies
Policies combine one or more requirements into a named authorization rule.

```csharp
services.AddAuthorization(options =>
{
    options.AddPolicy("Adult", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
});
```

### Authorization Context

The `AuthorizationHandlerContext` provides access to:
- **User**: The current user's claims principal
- **Resource**: The resource being accessed (optional)
- **Requirements**: The requirements being evaluated
- **PendingRequirements**: Requirements not yet satisfied

## Authorization Requirements

### Simple Requirements

Simple requirements contain basic criteria:

```csharp
public class MinimumExperienceRequirement : IAuthorizationRequirement
{
    public int MinimumYears { get; }
    
    public MinimumExperienceRequirement(int minimumYears)
    {
        MinimumYears = minimumYears;
    }
}
```

### Complex Requirements

Complex requirements can contain multiple parameters and validation logic:

```csharp
public class SecurityClearanceRequirement : IAuthorizationRequirement
{
    public string[] RequiredClearances { get; }
    public bool RequireAllClearances { get; }
    public DateTime? ExpirationCheck { get; }
    
    public SecurityClearanceRequirement(
        string[] requiredClearances, 
        bool requireAll = false,
        DateTime? expirationCheck = null)
    {
        RequiredClearances = requiredClearances;
        RequireAllClearances = requireAll;
        ExpirationCheck = expirationCheck;
    }
}
```

### Parameterized Requirements

Requirements can accept parameters for dynamic evaluation:

```csharp
public class BudgetApprovalRequirement : IAuthorizationRequirement
{
    public decimal MaxAmount { get; }
    public string Department { get; }
    
    public BudgetApprovalRequirement(decimal maxAmount, string department)
    {
        MaxAmount = maxAmount;
        Department = department;
    }
}
```

## Authorization Handlers

### Basic Handler Structure

```csharp
public class BasicHandler : AuthorizationHandler<SomeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SomeRequirement requirement)
    {
        // Evaluation logic here
        if (/* condition met */)
        {
            context.Succeed(requirement);
        }
        // Note: Don't call context.Fail() unless you want to prevent other handlers from succeeding
        
        return Task.CompletedTask;
    }
}
```

### Handler with Dependencies

Handlers can use dependency injection:

```csharp
public class DatabaseAuthorizationHandler : AuthorizationHandler<DatabaseRequirement>
{
    private readonly IUserService _userService;
    private readonly ILogger<DatabaseAuthorizationHandler> _logger;
    
    public DatabaseAuthorizationHandler(
        IUserService userService,
        ILogger<DatabaseAuthorizationHandler> logger)
    {
        _userService = userService;
        _logger = logger;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DatabaseRequirement requirement)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return;
        
        var userPermissions = await _userService.GetPermissionsAsync(userId);
        
        if (userPermissions.Contains(requirement.Permission))
        {
            _logger.LogInformation("User {UserId} granted {Permission}", userId, requirement.Permission);
            context.Succeed(requirement);
        }
    }
}
```

### Multiple Requirements Handler

A single handler can handle multiple requirements:

```csharp
public class MultiRequirementHandler : 
    IAuthorizationHandler
{
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        foreach (var requirement in context.PendingRequirements.ToList())
        {
            switch (requirement)
            {
                case MinimumAgeRequirement ageReq:
                    HandleAgeRequirement(context, ageReq);
                    break;
                case DepartmentRequirement deptReq:
                    HandleDepartmentRequirement(context, deptReq);
                    break;
            }
        }
        
        return Task.CompletedTask;
    }
    
    private void HandleAgeRequirement(AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
    {
        // Age handling logic
    }
    
    private void HandleDepartmentRequirement(AuthorizationHandlerContext context, DepartmentRequirement requirement)
    {
        // Department handling logic
    }
}
```

### Conditional Success and Failure

```csharp
public class ConditionalHandler : AuthorizationHandler<ConditionalRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ConditionalRequirement requirement)
    {
        var user = context.User;
        
        // Explicit success
        if (user.HasClaim("role", "admin"))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
        
        // Conditional logic
        if (user.HasClaim("role", "manager"))
        {
            var department = user.FindFirst("department")?.Value;
            if (department == requirement.RequiredDepartment)
            {
                context.Succeed(requirement);
            }
            else
            {
                // Explicit failure prevents other handlers from succeeding
                context.Fail();
            }
        }
        
        // Implicit failure - don't call Succeed() or Fail()
        return Task.CompletedTask;
    }
}
```

## Policy Configuration

### Simple Policies

```csharp
services.AddAuthorization(options =>
{
    // Single requirement
    options.AddPolicy("Adult", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
    
    // Multiple requirements (AND logic)
    options.AddPolicy("SeniorManager", policy =>
    {
        policy.Requirements.Add(new MinimumAgeRequirement(30));
        policy.Requirements.Add(new DepartmentRequirement("Management"));
        policy.Requirements.Add(new ExperienceRequirement(5));
    });
});
```

### Combining Claims and Requirements

```csharp
options.AddPolicy("FinanceAccess", policy =>
{
    // Claims-based requirements
    policy.RequireClaim("role", "manager", "admin");
    policy.RequireClaim("department", "finance");
    
    // Custom requirements
    policy.Requirements.Add(new SecurityClearanceRequirement(new[] { "Financial" }));
    policy.Requirements.Add(new BusinessHoursRequirement());
});
```

### Assertion-Based Policies

```csharp
options.AddPolicy("ComplexBusinessRule", policy =>
    policy.RequireAssertion(context =>
    {
        var user = context.User;
        
        // Complex business logic
        if (user.HasClaim("role", "CEO"))
            return true;
            
        if (user.HasClaim("role", "VP"))
        {
            var department = user.FindFirst("department")?.Value;
            var experience = user.FindFirst("experience")?.Value;
            
            return department == "Sales" && 
                   int.TryParse(experience, out int exp) && exp >= 10;
        }
        
        return false;
    }));
```

### Policy Builders

Create reusable policy builders:

```csharp
public static class PolicyBuilders
{
    public static AuthorizationPolicyBuilder RequireManagerRole(this AuthorizationPolicyBuilder builder)
    {
        return builder.RequireClaim("role", "manager", "admin");
    }
    
    public static AuthorizationPolicyBuilder RequireDepartment(this AuthorizationPolicyBuilder builder, params string[] departments)
    {
        return builder.Requirements.Add(new DepartmentRequirement(departments));
    }
    
    public static AuthorizationPolicyBuilder RequireBusinessHours(this AuthorizationPolicyBuilder builder)
    {
        return builder.Requirements.Add(new BusinessHoursRequirement());
    }
}

// Usage
options.AddPolicy("ManagerAccess", policy =>
    policy.RequireManagerRole()
          .RequireDepartment("Finance", "HR")
          .RequireBusinessHours());
```

## Resource-Based Authorization

### Resource Requirements

```csharp
public class DocumentAccessRequirement : IAuthorizationRequirement
{
    public string Operation { get; }
    
    public DocumentAccessRequirement(string operation)
    {
        Operation = operation;
    }
}

public static class Operations
{
    public static DocumentAccessRequirement Create = new("Create");
    public static DocumentAccessRequirement Read = new("Read");
    public static DocumentAccessRequirement Update = new("Update");
    public static DocumentAccessRequirement Delete = new("Delete");
}
```

### Resource Handlers

```csharp
public class DocumentAuthorizationHandler : 
    AuthorizationHandler<DocumentAccessRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentAccessRequirement requirement,
        Document resource)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        switch (requirement.Operation)
        {
            case "Create":
                // Anyone can create
                context.Succeed(requirement);
                break;
                
            case "Read":
                // Owner or admin can read
                if (resource.OwnerId == userId || context.User.HasClaim("role", "admin"))
                    context.Succeed(requirement);
                break;
                
            case "Update":
                // Only owner can update
                if (resource.OwnerId == userId)
                    context.Succeed(requirement);
                break;
                
            case "Delete":
                // Owner or admin can delete
                if (resource.OwnerId == userId || context.User.HasClaim("role", "admin"))
                    context.Succeed(requirement);
                break;
        }
        
        return Task.CompletedTask;
    }
}
```

### Using Resource-Based Authorization

```csharp
[HttpGet("{id}")]
public async Task<IActionResult> GetDocument(int id)
{
    var document = await _documentService.GetAsync(id);
    if (document == null)
        return NotFound();
    
    var authResult = await _authorizationService.AuthorizeAsync(
        User, document, Operations.Read);
    
    if (!authResult.Succeeded)
        return Forbid();
    
    return Ok(document);
}

[HttpPut("{id}")]
public async Task<IActionResult> UpdateDocument(int id, DocumentUpdateModel model)
{
    var document = await _documentService.GetAsync(id);
    if (document == null)
        return NotFound();
    
    var authResult = await _authorizationService.AuthorizeAsync(
        User, document, Operations.Update);
    
    if (!authResult.Succeeded)
        return Forbid();
    
    // Update logic here
    return Ok();
}
```

## Advanced Scenarios

### Hierarchical Authorization

```csharp
public class HierarchicalRequirement : IAuthorizationRequirement
{
    public string RequiredLevel { get; }
    
    public HierarchicalRequirement(string requiredLevel)
    {
        RequiredLevel = requiredLevel;
    }
}

public class HierarchicalHandler : AuthorizationHandler<HierarchicalRequirement>
{
    private static readonly Dictionary<string, int> Hierarchy = new()
    {
        { "Employee", 1 },
        { "Supervisor", 2 },
        { "Manager", 3 },
        { "Director", 4 },
        { "VP", 5 },
        { "CEO", 6 }
    };
    
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        HierarchicalRequirement requirement)
    {
        var userLevel = context.User.FindFirst("level")?.Value;
        
        if (userLevel != null && 
            Hierarchy.TryGetValue(userLevel, out int userRank) &&
            Hierarchy.TryGetValue(requirement.RequiredLevel, out int requiredRank) &&
            userRank >= requiredRank)
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}
```

### Time-Based Authorization

```csharp
public class TimeBasedRequirement : IAuthorizationRequirement
{
    public TimeSpan StartTime { get; }
    public TimeSpan EndTime { get; }
    public DayOfWeek[] AllowedDays { get; }
    
    public TimeBasedRequirement(TimeSpan startTime, TimeSpan endTime, params DayOfWeek[] allowedDays)
    {
        StartTime = startTime;
        EndTime = endTime;
        AllowedDays = allowedDays ?? new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday };
    }
}

public class TimeBasedHandler : AuthorizationHandler<TimeBasedRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TimeBasedRequirement requirement)
    {
        var now = DateTime.Now;
        var currentTime = now.TimeOfDay;
        var currentDay = now.DayOfWeek;
        
        if (requirement.AllowedDays.Contains(currentDay) &&
            currentTime >= requirement.StartTime &&
            currentTime <= requirement.EndTime)
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}
```

### Location-Based Authorization

```csharp
public class LocationRequirement : IAuthorizationRequirement
{
    public string[] AllowedLocations { get; }
    
    public LocationRequirement(params string[] allowedLocations)
    {
        AllowedLocations = allowedLocations;
    }
}

public class LocationHandler : AuthorizationHandler<LocationRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    
    public LocationHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        LocationRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var userLocation = httpContext?.Request.Headers["X-User-Location"].FirstOrDefault();
        
        if (userLocation != null && requirement.AllowedLocations.Contains(userLocation))
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}
```

### Dynamic Policy Creation

```csharp
public class DynamicPolicyProvider : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;
    
    public DynamicPolicyProvider(IOptions<AuthorizationOptions> options)
    {
        _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
    }
    
    public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
    {
        return _fallbackPolicyProvider.GetDefaultPolicyAsync();
    }
    
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
    {
        return _fallbackPolicyProvider.GetFallbackPolicyAsync();
    }
    
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith("MinimumAge"))
        {
            var age = int.Parse(policyName.Substring("MinimumAge".Length));
            var policy = new AuthorizationPolicyBuilder()
                .AddRequirements(new MinimumAgeRequirement(age))
                .Build();
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }
        
        return _fallbackPolicyProvider.GetPolicyAsync(policyName);
    }
}

// Usage: [Authorize(Policy = "MinimumAge21")]
```

## Best Practices

### 1. Requirement Design

```csharp
// Good: Single responsibility
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public MinimumAgeRequirement(int minimumAge) => MinimumAge = minimumAge;
}

// Avoid: Multiple responsibilities
public class UserValidationRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public string RequiredDepartment { get; }
    public bool RequireActiveStatus { get; }
    // Too many concerns in one requirement
}
```

### 2. Handler Organization

```csharp
// Good: Focused handler
public class AgeVerificationHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        // Single, focused responsibility
        var ageClaim = context.User.FindFirst("age");
        if (ageClaim != null && int.TryParse(ageClaim.Value, out int age) && age >= requirement.MinimumAge)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
```

### 3. Error Handling

```csharp
public class SafeHandler : AuthorizationHandler<SomeRequirement>
{
    private readonly ILogger<SafeHandler> _logger;
    
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SomeRequirement requirement)
    {
        try
        {
            // Authorization logic
            if (/* condition */)
            {
                context.Succeed(requirement);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in authorization handler");
            // Don't call context.Succeed() on error
            // Let the requirement fail naturally
        }
        
        return Task.CompletedTask;
    }
}
```

### 4. Testing Handlers

```csharp
[Test]
public async Task MinimumAgeHandler_WithValidAge_ShouldSucceed()
{
    // Arrange
    var requirement = new MinimumAgeRequirement(18);
    var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
    {
        new Claim("age", "25")
    }));
    var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);
    var handler = new MinimumAgeHandler();
    
    // Act
    await handler.HandleAsync(context);
    
    // Assert
    Assert.True(context.HasSucceeded);
}
```

### 5. Policy Constants

```csharp
public static class Policies
{
    public const string RequireAdminRole = "RequireAdminRole";
    public const string RequireManagerRole = "RequireManagerRole";
    public const string RequireHRDepartment = "RequireHRDepartment";
    public const string RequireBusinessHours = "RequireBusinessHours";
}

// Usage
[Authorize(Policy = Policies.RequireAdminRole)]
public class AdminController : ControllerBase { }
```

## Performance Considerations

### 1. Handler Efficiency

```csharp
// Efficient: Early returns
public class EfficientHandler : AuthorizationHandler<SomeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SomeRequirement requirement)
    {
        // Quick checks first
        if (!context.User.Identity?.IsAuthenticated ?? true)
            return Task.CompletedTask;
        
        var roleClaim = context.User.FindFirst("role");
        if (roleClaim == null)
            return Task.CompletedTask;
        
        // More expensive operations last
        if (roleClaim.Value == "admin")
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}
```

### 2. Caching

```csharp
public class CachedAuthorizationHandler : AuthorizationHandler<DatabaseRequirement>
{
    private readonly IMemoryCache _cache;
    private readonly IUserService _userService;
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DatabaseRequirement requirement)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return;
        
        var cacheKey = $"permissions_{userId}";
        
        if (!_cache.TryGetValue(cacheKey, out HashSet<string> permissions))
        {
            var userPermissions = await _userService.GetPermissionsAsync(userId);
            permissions = new HashSet<string>(userPermissions);
            _cache.Set(cacheKey, permissions, TimeSpan.FromMinutes(15));
        }
        
        if (permissions.Contains(requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}
```

### 3. Async Operations

```csharp
public class AsyncHandler : AuthorizationHandler<AsyncRequirement>
{
    private readonly IExternalService _externalService;
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AsyncRequirement requirement)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null) return;
        
        // Use ConfigureAwait(false) for library code
        var isAuthorized = await _externalService
            .CheckAuthorizationAsync(userId, requirement.Resource)
            .ConfigureAwait(false);
        
        if (isAuthorized)
        {
            context.Succeed(requirement);
        }
    }
}
```

## Testing Strategies

### Unit Testing Requirements

```csharp
[Test]
public void MinimumAgeRequirement_ShouldStoreAge()
{
    // Arrange & Act
    var requirement = new MinimumAgeRequirement(21);
    
    // Assert
    Assert.AreEqual(21, requirement.MinimumAge);
}
```

### Unit Testing Handlers

```csharp
[TestFixture]
public class MinimumAgeHandlerTests
{
    private MinimumAgeHandler _handler;
    
    [SetUp]
    public void Setup()
    {
        _handler = new MinimumAgeHandler();
    }
    
    [Test]
    public async Task HandleRequirementAsync_UserMeetsAge_ShouldSucceed()
    {
        // Arrange
        var requirement = new MinimumAgeRequirement(18);
        var claims = new[] { new Claim("age", "25") };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);
        
        // Act
        await _handler.HandleAsync(context);
        
        // Assert
        Assert.True(context.HasSucceeded);
    }
    
    [Test]
    public async Task HandleRequirementAsync_UserTooYoung_ShouldNotSucceed()
    {
        // Arrange
        var requirement = new MinimumAgeRequirement(18);
        var claims = new[] { new Claim("age", "16") };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);
        
        // Act
        await _handler.HandleAsync(context);
        
        // Assert
        Assert.False(context.HasSucceeded);
    }
}
```

### Integration Testing

```csharp
[Test]
public async Task GetProtectedResource_WithValidPolicy_ShouldReturnOk()
{
    // Arrange
    var client = _factory.CreateClient();
    
    // Login and get authentication cookie
    var loginResponse = await client.PostAsync("/login", 
        new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", "testuser"),
            new KeyValuePair<string, string>("age", "25")
        }));
    
    var cookies = loginResponse.Headers.GetValues("Set-Cookie");
    client.DefaultRequestHeaders.Add("Cookie", cookies);
    
    // Act
    var response = await client.GetAsync("/adult-content");
    
    // Assert
    Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
}
```

### Testing with Custom WebApplicationFactory

```csharp
public class AuthorizationTestFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Replace real services with test doubles
            services.AddScoped<IUserService, MockUserService>();
            
            // Override authorization handlers for testing
            services.AddScoped<IAuthorizationHandler, TestAuthorizationHandler>();
        });
    }
}
```

## Troubleshooting

### Common Issues

#### 1. Handler Not Called

**Problem**: Authorization handler is not being executed.

**Solutions**:
- Ensure handler is registered in DI container
- Check that requirement is added to policy
- Verify policy name matches usage

```csharp
// Registration
services.AddScoped<IAuthorizationHandler, MyHandler>();

// Policy configuration
options.AddPolicy("MyPolicy", policy =>
    policy.Requirements.Add(new MyRequirement()));

// Usage
[Authorize(Policy = "MyPolicy")]
```

#### 2. Always Failing Authorization

**Problem**: Authorization always fails even with correct claims.

**Debugging**:
```csharp
public class DebugHandler : AuthorizationHandler<DebugRequirement>
{
    private readonly ILogger<DebugHandler> _logger;
    
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DebugRequirement requirement)
    {
        _logger.LogInformation("User: {User}", context.User.Identity?.Name);
        _logger.LogInformation("Claims: {Claims}", 
            string.Join(", ", context.User.Claims.Select(c => $"{c.Type}={c.Value}")));
        _logger.LogInformation("Requirements: {Requirements}",
            string.Join(", ", context.Requirements.Select(r => r.GetType().Name)));
        
        // Your logic here
        
        return Task.CompletedTask;
    }
}
```

#### 3. Multiple Handlers Conflict

**Problem**: Multiple handlers for the same requirement causing issues.

**Solution**: Use explicit success/failure:
```csharp
public class ConflictResolutionHandler : AuthorizationHandler<ConflictRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ConflictRequirement requirement)
    {
        if (/* explicit deny condition */)
        {
            context.Fail(); // Prevents other handlers from succeeding
            return Task.CompletedTask;
        }
        
        if (/* success condition */)
        {
            context.Succeed(requirement);
        }
        
        // Implicit failure - allows other handlers to try
        return Task.CompletedTask;
    }
}
```

### Debugging Tools

```csharp
public class AuthorizationLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuthorizationLoggingMiddleware> _logger;
    
    public AuthorizationLoggingMiddleware(RequestDelegate next, ILogger<AuthorizationLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        _logger.LogInformation("Request: {Method} {Path}", context.Request.Method, context.Request.Path);
        _logger.LogInformation("User: {User}", context.User.Identity?.Name);
        _logger.LogInformation("Authenticated: {IsAuthenticated}", context.User.Identity?.IsAuthenticated);
        
        await _next(context);
        
        _logger.LogInformation("Response: {StatusCode}", context.Response.StatusCode);
    }
}
```

## Conclusion

Policy-based authorization in ASP.NET Core provides unparalleled flexibility for implementing complex authorization scenarios. By understanding requirements, handlers, and policies, you can create sophisticated authorization systems that accurately reflect your business rules.

### Key Takeaways

1. **Separation of Concerns**: Requirements define what to check, handlers define how to check
2. **Flexibility**: Combine multiple requirements and handlers for complex scenarios
3. **Testability**: Each component can be unit tested independently
4. **Reusability**: Requirements and handlers can be reused across different policies
5. **Performance**: Design handlers for efficiency and consider caching strategies
6. **Maintainability**: Keep requirements focused and handlers simple

### When to Use Policy-Based Authorization

- **Complex Business Rules**: When simple role/claim checks aren't sufficient
- **Resource-Based Access**: When authorization depends on the specific resource
- **Dynamic Requirements**: When authorization rules change based on context
- **Audit Requirements**: When you need detailed authorization logging
- **Multi-Tenant Applications**: When authorization varies by tenant

Policy-based authorization scales from simple applications to complex enterprise systems, making it an excellent choice for applications with sophisticated security requirements.

### Further Reading

- [ASP.NET Core Authorization Documentation](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/)
- [Policy-based Authorization](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies)
- [Resource-based Authorization](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased)
- [Custom Authorization Policy Providers](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/iauthorizationpolicyprovider)