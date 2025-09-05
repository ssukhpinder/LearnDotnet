# Complete Guide to API Key Authentication in ASP.NET Core

## Table of Contents
1. [Introduction](#introduction)
2. [What is API Key Authentication?](#what-is-api-key-authentication)
3. [When to Use API Keys](#when-to-use-api-keys)
4. [Implementation Approaches](#implementation-approaches)
5. [Step-by-Step Implementation](#step-by-step-implementation)
6. [Security Best Practices](#security-best-practices)
7. [Advanced Scenarios](#advanced-scenarios)
8. [Testing and Validation](#testing-and-validation)
9. [Production Considerations](#production-considerations)
10. [Conclusion](#conclusion)

## Introduction

API key authentication is one of the simplest and most widely used authentication mechanisms for web APIs. This guide provides a comprehensive overview of implementing API key authentication in ASP.NET Core applications.

## What is API Key Authentication?

API key authentication is a method where clients authenticate by including a secret key (API key) in their requests. The server validates this key before granting access to protected resources.

### Key Characteristics:
- **Stateless**: No session management required
- **Simple**: Easy to implement and understand
- **Scalable**: Works well in distributed systems
- **Flexible**: Can be passed in headers, query parameters, or request body

### Common Use Cases:
- Public APIs with usage tracking
- Service-to-service communication
- Third-party integrations
- Mobile app backends

## When to Use API Keys

### Ideal Scenarios:
- **Machine-to-machine communication**: Perfect for automated systems
- **Public APIs**: When you need to track usage per client
- **Simple authentication needs**: When OAuth or JWT is overkill
- **Legacy system integration**: Easy to implement in existing systems

### Not Recommended For:
- **User authentication**: Use JWT or session-based auth instead
- **Highly sensitive data**: Consider stronger authentication methods
- **Complex authorization**: When you need role-based access control

## Implementation Approaches

### 1. Middleware Approach (Recommended)
- Global application of authentication
- Clean separation of concerns
- Easy to configure and maintain

### 2. Action Filter Approach
- Granular control over which endpoints require authentication
- Attribute-based configuration
- Good for selective protection

### 3. Authorization Handler Approach
- Integration with ASP.NET Core's authorization system
- Policy-based authorization
- Most flexible but more complex

## Step-by-Step Implementation

### Step 1: Create the Middleware

```csharp
public class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private const string ApiKeyHeaderName = "X-API-Key";
    private const string ValidApiKey = "my-secret-api-key-123";

    public ApiKeyMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(ApiKeyHeaderName, out var extractedApiKey))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("API Key missing");
            return;
        }

        if (!ValidApiKey.Equals(extractedApiKey))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Invalid API Key");
            return;
        }

        await _next(context);
    }
}
```

### Step 2: Register the Middleware

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var app = builder.Build();

app.UseMiddleware<ApiKeyMiddleware>();
app.MapControllers();

app.Run();
```

### Step 3: Create Protected Controllers

```csharp
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
```

## Security Best Practices

### 1. Secure Key Storage
```csharp
// Use configuration instead of hardcoded values
private readonly string _validApiKey;

public ApiKeyMiddleware(RequestDelegate next, IConfiguration configuration)
{
    _next = next;
    _validApiKey = configuration["ApiKey"] ?? throw new InvalidOperationException("API Key not configured");
}
```

### 2. Multiple API Keys Support
```csharp
private readonly HashSet<string> _validApiKeys;

public ApiKeyMiddleware(RequestDelegate next, IConfiguration configuration)
{
    _next = next;
    _validApiKeys = configuration.GetSection("ApiKeys").Get<string[]>()?.ToHashSet() 
        ?? throw new InvalidOperationException("API Keys not configured");
}
```

### 3. Rate Limiting
```csharp
// Implement rate limiting per API key
private readonly Dictionary<string, DateTime> _lastRequestTimes = new();
private readonly TimeSpan _rateLimitWindow = TimeSpan.FromSeconds(1);

public async Task InvokeAsync(HttpContext context)
{
    var apiKey = context.Request.Headers["X-API-Key"].FirstOrDefault();
    
    if (_lastRequestTimes.TryGetValue(apiKey, out var lastRequest))
    {
        if (DateTime.UtcNow - lastRequest < _rateLimitWindow)
        {
            context.Response.StatusCode = 429;
            await context.Response.WriteAsync("Rate limit exceeded");
            return;
        }
    }
    
    _lastRequestTimes[apiKey] = DateTime.UtcNow;
    // Continue with authentication...
}
```

### 4. Logging and Monitoring
```csharp
private readonly ILogger<ApiKeyMiddleware> _logger;

public async Task InvokeAsync(HttpContext context)
{
    var apiKey = context.Request.Headers["X-API-Key"].FirstOrDefault();
    
    if (string.IsNullOrEmpty(apiKey))
    {
        _logger.LogWarning("API request without key from {IP}", context.Connection.RemoteIpAddress);
        // Handle missing key...
    }
    
    if (!_validApiKeys.Contains(apiKey))
    {
        _logger.LogWarning("Invalid API key attempt: {Key} from {IP}", apiKey, context.Connection.RemoteIpAddress);
        // Handle invalid key...
    }
    
    _logger.LogInformation("Successful API key authentication for {Key}", apiKey);
}
```

## Advanced Scenarios

### 1. Key-Based Authorization
```csharp
public class ApiKeyAuthorizationMiddleware
{
    private readonly Dictionary<string, string[]> _keyPermissions = new()
    {
        { "admin-key-123", new[] { "read", "write", "delete" } },
        { "read-only-key-456", new[] { "read" } }
    };

    public async Task InvokeAsync(HttpContext context)
    {
        var apiKey = context.Request.Headers["X-API-Key"].FirstOrDefault();
        var permissions = _keyPermissions.GetValueOrDefault(apiKey, Array.Empty<string>());
        
        context.Items["ApiKeyPermissions"] = permissions;
        await _next(context);
    }
}
```

### 2. Database-Stored Keys
```csharp
public class DatabaseApiKeyMiddleware
{
    private readonly IApiKeyService _apiKeyService;

    public async Task InvokeAsync(HttpContext context)
    {
        var apiKey = context.Request.Headers["X-API-Key"].FirstOrDefault();
        
        if (string.IsNullOrEmpty(apiKey))
        {
            context.Response.StatusCode = 401;
            return;
        }

        var keyInfo = await _apiKeyService.ValidateKeyAsync(apiKey);
        if (keyInfo == null || !keyInfo.IsActive)
        {
            context.Response.StatusCode = 401;
            return;
        }

        context.Items["ApiKeyInfo"] = keyInfo;
        await _next(context);
    }
}
```

### 3. Scoped API Keys
```csharp
[ApiController]
[Route("[controller]")]
public class ScopedController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult GetPublicData() => Ok("Public data");

    [HttpGet("private")]
    public IActionResult GetPrivateData()
    {
        var permissions = HttpContext.Items["ApiKeyPermissions"] as string[];
        if (permissions?.Contains("read") != true)
        {
            return Forbid("Insufficient permissions");
        }
        
        return Ok("Private data");
    }
}
```

## Testing and Validation

### Unit Testing the Middleware
```csharp
[Test]
public async Task ApiKeyMiddleware_ValidKey_CallsNext()
{
    var context = new DefaultHttpContext();
    context.Request.Headers["X-API-Key"] = "valid-key";
    
    var nextCalled = false;
    RequestDelegate next = (ctx) => { nextCalled = true; return Task.CompletedTask; };
    
    var middleware = new ApiKeyMiddleware(next);
    await middleware.InvokeAsync(context);
    
    Assert.IsTrue(nextCalled);
}

[Test]
public async Task ApiKeyMiddleware_InvalidKey_Returns401()
{
    var context = new DefaultHttpContext();
    context.Request.Headers["X-API-Key"] = "invalid-key";
    context.Response.Body = new MemoryStream();
    
    var middleware = new ApiKeyMiddleware(_ => Task.CompletedTask);
    await middleware.InvokeAsync(context);
    
    Assert.AreEqual(401, context.Response.StatusCode);
}
```

### Integration Testing
```csharp
[Test]
public async Task SecureEndpoint_WithValidKey_ReturnsData()
{
    var client = _factory.CreateClient();
    client.DefaultRequestHeaders.Add("X-API-Key", "valid-key");
    
    var response = await client.GetAsync("/secure/data");
    
    response.EnsureSuccessStatusCode();
    var content = await response.Content.ReadAsStringAsync();
    Assert.Contains("protected data", content);
}
```

## Production Considerations

### 1. Configuration Management
```json
{
  "ApiKeys": [
    "prod-key-1",
    "prod-key-2"
  ],
  "ApiKeySettings": {
    "HeaderName": "X-API-Key",
    "RateLimitPerSecond": 10
  }
}
```

### 2. Environment Variables
```csharp
var apiKeys = Environment.GetEnvironmentVariable("API_KEYS")?.Split(',') 
    ?? throw new InvalidOperationException("API_KEYS environment variable not set");
```

### 3. Azure Key Vault Integration
```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{keyVaultName}.vault.azure.net/"),
    new DefaultAzureCredential());
```

### 4. Health Checks
```csharp
builder.Services.AddHealthChecks()
    .AddCheck<ApiKeyHealthCheck>("api-key-validation");
```

### 5. Metrics and Monitoring
```csharp
private readonly Counter<int> _authenticationAttempts;
private readonly Counter<int> _authenticationFailures;

public ApiKeyMiddleware(RequestDelegate next, IMeterFactory meterFactory)
{
    _next = next;
    var meter = meterFactory.Create("ApiKeyAuth");
    _authenticationAttempts = meter.CreateCounter<int>("api_key_attempts");
    _authenticationFailures = meter.CreateCounter<int>("api_key_failures");
}
```

## Conclusion

API key authentication provides a simple yet effective way to secure your ASP.NET Core APIs. While it may not be suitable for all scenarios, it excels in machine-to-machine communication and public API access control.

Key takeaways:
- Use middleware for global API key enforcement
- Store keys securely using configuration or key vaults
- Implement proper logging and monitoring
- Consider rate limiting and usage tracking
- Test thoroughly with both unit and integration tests

Remember that API key authentication should be part of a broader security strategy that includes HTTPS, input validation, and proper error handling.