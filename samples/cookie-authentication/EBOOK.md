# Complete Guide to Cookie-Based Authentication in ASP.NET Core

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding Cookie Authentication](#understanding-cookie-authentication)
3. [Setting Up Cookie Authentication](#setting-up-cookie-authentication)
4. [Implementation Details](#implementation-details)
5. [Security Considerations](#security-considerations)
6. [Advanced Scenarios](#advanced-scenarios)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Introduction

Cookie-based authentication is one of the most common authentication mechanisms for web applications. In ASP.NET Core, it provides a stateful authentication approach where user credentials are validated once, and subsequent requests are authenticated using a secure cookie.

### When to Use Cookie Authentication
- Traditional web applications with server-side rendering
- Applications where users expect to stay logged in across browser sessions
- Internal applications where you control both client and server
- When you need simple, built-in session management

### When NOT to Use Cookie Authentication
- Single Page Applications (SPAs) that consume APIs
- Mobile applications
- Cross-origin API consumption
- Microservices architectures (prefer JWT tokens)

## Understanding Cookie Authentication

### How It Works
1. **Login Process**: User submits credentials
2. **Validation**: Server validates credentials
3. **Cookie Creation**: Server creates an encrypted authentication cookie
4. **Cookie Storage**: Browser automatically stores the cookie
5. **Subsequent Requests**: Browser sends cookie with each request
6. **Automatic Authentication**: Server decrypts and validates cookie

### Cookie Structure
ASP.NET Core authentication cookies contain:
- **Claims**: User identity information (name, roles, custom claims)
- **Expiration**: When the cookie expires
- **Security Stamp**: Prevents cookie replay attacks
- **Encryption**: Data is encrypted using Data Protection API

## Setting Up Cookie Authentication

### Basic Configuration
```csharp
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/auth/login";
        options.LogoutPath = "/auth/logout";
        options.AccessDeniedPath = "/auth/access-denied";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
    });
```

### Configuration Options Explained

#### Essential Options
- **LoginPath**: Redirect URL when authentication is required
- **LogoutPath**: URL for logout operations
- **ExpireTimeSpan**: How long cookies remain valid
- **SlidingExpiration**: Extends expiration on each request

#### Security Options
- **Cookie.HttpOnly**: Prevents JavaScript access (default: true)
- **Cookie.Secure**: Requires HTTPS (default: true in production)
- **Cookie.SameSite**: CSRF protection (default: Lax)

#### Advanced Options
- **ReturnUrlParameter**: Query parameter for return URLs
- **AccessDeniedPath**: Redirect for authorization failures
- **Events**: Custom event handlers for authentication lifecycle

## Implementation Details

### Creating Authentication Claims
```csharp
var claims = new List<Claim>
{
    new(ClaimTypes.Name, username),
    new(ClaimTypes.Email, email),
    new(ClaimTypes.Role, "User"),
    new("CustomClaim", "CustomValue")
};

var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
var principal = new ClaimsPrincipal(identity);
```

### Sign In Process
```csharp
await HttpContext.SignInAsync(
    CookieAuthenticationDefaults.AuthenticationScheme, 
    principal,
    new AuthenticationProperties
    {
        IsPersistent = true, // Remember me functionality
        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
    });
```

### Sign Out Process
```csharp
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
```

### Accessing User Information
```csharp
// In controllers
var username = User.Identity?.Name;
var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value);

// Check authentication status
if (User.Identity?.IsAuthenticated == true)
{
    // User is authenticated
}
```

## Security Considerations

### Data Protection
ASP.NET Core uses the Data Protection API to encrypt cookies:
```csharp
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"c:\keys"))
    .SetApplicationName("MyApp");
```

### Cookie Security Settings
```csharp
.AddCookie(options =>
{
    options.Cookie.Name = "MyAppAuth";
    options.Cookie.HttpOnly = true;
    options.Cookie.Secure = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
```

### HTTPS Requirements
Always use HTTPS in production:
```csharp
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Strict;
    options.Secure = CookieSecurePolicy.Always;
});
```

### Anti-Forgery Protection
```csharp
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "__RequestVerificationToken";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});
```

## Advanced Scenarios

### Multiple Authentication Schemes
```csharp
builder.Services.AddAuthentication()
    .AddCookie("AdminScheme", options =>
    {
        options.LoginPath = "/admin/login";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddCookie("UserScheme", options =>
    {
        options.LoginPath = "/user/login";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    });
```

### Custom Cookie Events
```csharp
.AddCookie(options =>
{
    options.Events = new CookieAuthenticationEvents
    {
        OnValidatePrincipal = async context =>
        {
            // Custom validation logic
            var userService = context.HttpContext.RequestServices.GetService<IUserService>();
            var isValid = await userService.ValidateUserAsync(context.Principal);
            
            if (!isValid)
            {
                context.RejectPrincipal();
                await context.HttpContext.SignOutAsync();
            }
        },
        OnRedirectToLogin = context =>
        {
            // Custom redirect logic for API endpoints
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = 401;
                return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        }
    };
});
```

### Role-Based Authorization
```csharp
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase { }

[Authorize(Roles = "Admin,Manager")]
public IActionResult SecureAction() { }
```

### Policy-Based Authorization
```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin"));
    
    options.AddPolicy("MinimumAge", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Age" && 
            int.Parse(c.Value) >= 18)));
});

[Authorize(Policy = "RequireAdminRole")]
public IActionResult AdminOnly() { }
```

## Best Practices

### 1. Secure Configuration
- Always use HTTPS in production
- Set appropriate cookie expiration times
- Enable sliding expiration for better UX
- Use secure cookie settings

### 2. Claims Management
- Keep claims minimal and relevant
- Avoid storing sensitive data in claims
- Use consistent claim types
- Implement claim transformation if needed

### 3. Session Management
- Implement proper logout functionality
- Handle session timeouts gracefully
- Provide session extension mechanisms
- Monitor and log authentication events

### 4. Error Handling
```csharp
app.UseExceptionHandler("/error");
app.UseStatusCodePagesWithReExecute("/error/{0}");
```

### 5. Logging and Monitoring
```csharp
builder.Services.Configure<CookieAuthenticationOptions>(options =>
{
    options.Events.OnSignedIn = context =>
    {
        var logger = context.HttpContext.RequestServices.GetService<ILogger<Program>>();
        logger.LogInformation("User {User} signed in", context.Principal.Identity.Name);
        return Task.CompletedTask;
    };
});
```

## Troubleshooting

### Common Issues

#### 1. Cookies Not Being Set
**Problem**: Authentication appears successful but cookies aren't created.
**Solutions**:
- Check HTTPS requirements in development
- Verify cookie domain and path settings
- Ensure proper middleware order

#### 2. Authentication Not Persisting
**Problem**: Users get logged out unexpectedly.
**Solutions**:
- Check cookie expiration settings
- Verify Data Protection configuration
- Ensure consistent application names across instances

#### 3. CORS Issues
**Problem**: Authentication fails in cross-origin scenarios.
**Solutions**:
```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowCredentials", policy =>
    {
        policy.WithOrigins("https://localhost:3000")
              .AllowCredentials()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});
```

#### 4. Load Balancer Issues
**Problem**: Authentication fails in load-balanced environments.
**Solutions**:
- Configure shared Data Protection keys
- Use distributed cache for session storage
- Ensure consistent machine keys

### Debugging Tips

#### Enable Detailed Logging
```csharp
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);
```

#### Inspect Cookies
Use browser developer tools to examine:
- Cookie presence and values
- Expiration times
- Security flags
- Domain and path settings

#### Custom Middleware for Debugging
```csharp
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetService<ILogger<Program>>();
    logger.LogInformation("Auth: {IsAuth}, User: {User}", 
        context.User.Identity?.IsAuthenticated, 
        context.User.Identity?.Name);
    await next();
});
```

## Conclusion

Cookie-based authentication in ASP.NET Core provides a robust, secure, and user-friendly authentication mechanism for web applications. By following the patterns and practices outlined in this guide, you can implement a secure authentication system that meets your application's requirements while maintaining good security posture.

Remember to always consider your specific use case, security requirements, and user experience when implementing authentication. Regular security reviews and updates are essential to maintain a secure application.