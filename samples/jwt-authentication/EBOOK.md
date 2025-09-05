# Complete Guide to JWT Authentication in ASP.NET Core

## Table of Contents
1. [Introduction to JWT](#introduction-to-jwt)
2. [JWT Structure and Components](#jwt-structure-and-components)
3. [Setting Up JWT Authentication](#setting-up-jwt-authentication)
4. [Implementation Details](#implementation-details)
5. [Security Considerations](#security-considerations)
6. [Advanced Scenarios](#advanced-scenarios)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Introduction to JWT

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.

### When to Use JWT

JWT is useful for:
- **Authorization**: Most common scenario. Once logged in, each subsequent request includes the JWT, allowing access to routes, services, and resources
- **Information Exchange**: Securely transmitting information between parties
- **Stateless Authentication**: No need to store session information on the server

### JWT vs Other Authentication Methods

| Method | Storage | Scalability | Security | Complexity |
|--------|---------|-------------|----------|------------|
| JWT | Client-side | High | Good | Medium |
| Session Cookies | Server-side | Medium | Good | Low |
| API Keys | Client-side | High | Medium | Low |

## JWT Structure and Components

A JWT consists of three parts separated by dots (.):
```
header.payload.signature
```

### Header
Contains metadata about the token:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload
Contains the claims (statements about an entity):
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622
}
```

### Signature
Ensures the token hasn't been tampered with:
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

## Setting Up JWT Authentication

### 1. Install Required Packages

```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="9.0.8" />
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.2.1" />
```

### 2. Configure JWT in Program.cs

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();

// JWT Configuration
var jwtKey = builder.Configuration["Jwt:Key"] ?? "YourSecretKey";
var key = Encoding.ASCII.GetBytes(jwtKey);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

var app = builder.Build();

// Configure pipeline
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

### 3. Configuration Settings

Add to `appsettings.json`:
```json
{
  "Jwt": {
    "Key": "YourSuperSecretKeyThatIsAtLeast32CharactersLong",
    "Issuer": "YourAppName",
    "Audience": "YourAppUsers",
    "ExpiryMinutes": 60
  }
}
```

## Implementation Details

### Token Generation Service

Create a dedicated service for JWT operations:

```csharp
public interface IJwtService
{
    string GenerateToken(string userId, string username, IEnumerable<string> roles);
    ClaimsPrincipal? ValidateToken(string token);
}

public class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _key;

    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
        var keyString = _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured");
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));
    }

    public string GenerateToken(string userId, string username, IEnumerable<string> roles)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Name, username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:ExpiryMinutes"] ?? "60")),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256Signature)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _key,
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }
}
```

### Enhanced Authentication Controller

```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtService _jwtService;
    private readonly IUserService _userService;

    public AuthController(IJwtService jwtService, IUserService userService)
    {
        _jwtService = jwtService;
        _userService = userService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userService.ValidateUserAsync(request.Username, request.Password);
        if (user == null)
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }

        var roles = await _userService.GetUserRolesAsync(user.Id);
        var token = _jwtService.GenerateToken(user.Id.ToString(), user.Username, roles);

        return Ok(new LoginResponse
        {
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60),
            User = new UserInfo
            {
                Id = user.Id,
                Username = user.Username,
                Roles = roles.ToList()
            }
        });
    }

    [HttpPost("refresh")]
    [Authorize]
    public IActionResult RefreshToken()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = User.FindFirst(ClaimTypes.Name)?.Value;
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value);

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(username))
        {
            return Unauthorized();
        }

        var newToken = _jwtService.GenerateToken(userId, username, roles);
        return Ok(new { token = newToken });
    }
}
```

### Role-Based Authorization

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    [Authorize(Roles = "Admin")]
    public IActionResult GetUsers()
    {
        return Ok(new { message = "Admin-only data" });
    }

    [HttpGet("reports")]
    [Authorize(Roles = "Admin,Manager")]
    public IActionResult GetReports()
    {
        return Ok(new { message = "Admin or Manager data" });
    }
}
```

### Custom Authorization Policies

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
    options.AddPolicy("RequireManagerOrAdmin", policy => 
        policy.RequireAssertion(context =>
            context.User.IsInRole("Admin") || context.User.IsInRole("Manager")));
});

// Usage in controller
[HttpGet("sensitive-data")]
[Authorize(Policy = "RequireAdminRole")]
public IActionResult GetSensitiveData()
{
    return Ok(new { data = "Very sensitive information" });
}
```

## Security Considerations

### 1. Secret Key Management

**Never hardcode secrets in production:**

```csharp
// ❌ Bad - Hardcoded secret
var key = "MyHardcodedSecret123";

// ✅ Good - From configuration
var key = builder.Configuration["Jwt:Key"];

// ✅ Better - From environment variable
var key = Environment.GetEnvironmentVariable("JWT_SECRET_KEY");

// ✅ Best - From Azure Key Vault or similar
var key = await keyVaultClient.GetSecretAsync("jwt-secret-key");
```

### 2. Token Expiration

Implement appropriate token lifetimes:

```csharp
var tokenDescriptor = new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(claims),
    Expires = DateTime.UtcNow.AddMinutes(15), // Short-lived access token
    // ... other properties
};
```

### 3. Refresh Token Implementation

```csharp
public class RefreshTokenService
{
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public async Task<bool> ValidateRefreshTokenAsync(string token, string userId)
    {
        // Check if refresh token exists and is valid in database
        var storedToken = await _repository.GetRefreshTokenAsync(token);
        return storedToken != null && 
               storedToken.UserId == userId && 
               storedToken.ExpiryDate > DateTime.UtcNow;
    }
}
```

### 4. Token Blacklisting

For logout functionality:

```csharp
public class TokenBlacklistService
{
    private readonly IMemoryCache _cache;

    public TokenBlacklistService(IMemoryCache cache)
    {
        _cache = cache;
    }

    public void BlacklistToken(string jti, DateTime expiry)
    {
        _cache.Set($"blacklist_{jti}", true, expiry);
    }

    public bool IsTokenBlacklisted(string jti)
    {
        return _cache.TryGetValue($"blacklist_{jti}", out _);
    }
}
```

## Advanced Scenarios

### 1. Multiple JWT Issuers

```csharp
builder.Services.AddAuthentication()
    .AddJwtBearer("Internal", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "InternalApp",
            // ... other parameters
        };
    })
    .AddJwtBearer("External", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "ExternalProvider",
            // ... other parameters
        };
    });

// Usage
[Authorize(AuthenticationSchemes = "Internal")]
public class InternalController : ControllerBase { }
```

### 2. Custom Claims

```csharp
var claims = new List<Claim>
{
    new(ClaimTypes.NameIdentifier, user.Id.ToString()),
    new(ClaimTypes.Name, user.Username),
    new("department", user.Department),
    new("permission", "read:users"),
    new("permission", "write:reports")
};
```

### 3. JWT with OpenID Connect

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = "oidc";
})
.AddCookie("Cookies")
.AddOpenIdConnect("oidc", options =>
{
    options.Authority = "https://your-identity-provider.com";
    options.ClientId = "your-client-id";
    options.ClientSecret = "your-client-secret";
    options.ResponseType = "code";
    options.SaveTokens = true;
});
```

## Best Practices

### 1. Token Structure

- Keep payload minimal to reduce token size
- Use standard claims when possible
- Avoid sensitive information in tokens

### 2. Security Headers

```csharp
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    await next();
});
```

### 3. HTTPS Only

```csharp
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}
```

### 4. Rate Limiting

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("AuthPolicy", opt =>
    {
        opt.PermitLimit = 5;
        opt.Window = TimeSpan.FromMinutes(1);
    });
});

[EnableRateLimiting("AuthPolicy")]
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // Login logic
}
```

### 5. Logging and Monitoring

```csharp
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        _logger.LogInformation("Login attempt for user: {Username}", request.Username);
        
        var user = await _userService.ValidateUserAsync(request.Username, request.Password);
        if (user == null)
        {
            _logger.LogWarning("Failed login attempt for user: {Username}", request.Username);
            return Unauthorized();
        }

        _logger.LogInformation("Successful login for user: {Username}", request.Username);
        // Generate token...
    }
}
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized despite valid token**
   - Check token expiration
   - Verify signing key matches
   - Ensure proper Authorization header format: `Bearer <token>`

2. **Token validation fails**
   - Verify issuer and audience settings
   - Check clock skew settings
   - Ensure token hasn't been tampered with

3. **Claims not found**
   - Verify claim names match exactly
   - Check if claims were added during token generation
   - Ensure proper claim types are used

### Debugging Tips

```csharp
// Enable detailed JWT logging
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication.JwtBearer", LogLevel.Debug);

// Custom middleware to log token details
app.Use(async (context, next) =>
{
    if (context.Request.Headers.ContainsKey("Authorization"))
    {
        var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
        var handler = new JwtSecurityTokenHandler();
        if (handler.CanReadToken(token))
        {
            var jsonToken = handler.ReadJwtToken(token);
            Console.WriteLine($"Token expires: {jsonToken.ValidTo}");
            Console.WriteLine($"Token claims: {string.Join(", ", jsonToken.Claims.Select(c => $"{c.Type}:{c.Value}"))}");
        }
    }
    await next();
});
```

### Testing JWT Endpoints

```bash
# Get token
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Use token
curl -X GET https://localhost:5001/api/secure/data \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

## Conclusion

JWT authentication provides a robust, scalable solution for securing ASP.NET Core applications. By following the patterns and best practices outlined in this guide, you can implement secure, maintainable authentication systems that scale with your application needs.

Remember to always prioritize security, use HTTPS in production, manage secrets properly, and implement appropriate token expiration and refresh mechanisms.