# OAuth 2.0 and OpenID Connect Authentication in ASP.NET Core

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding OAuth 2.0](#understanding-oauth-20)
3. [Understanding OpenID Connect](#understanding-openid-connect)
4. [Implementation in ASP.NET Core](#implementation-in-aspnet-core)
5. [Security Best Practices](#security-best-practices)
6. [Troubleshooting](#troubleshooting)

## Introduction

OAuth 2.0 and OpenID Connect are fundamental protocols for modern web authentication and authorization. This guide provides a comprehensive understanding of how to implement these protocols in ASP.NET Core applications.

### What You'll Learn
- OAuth 2.0 authorization flows
- OpenID Connect authentication layer
- ASP.NET Core authentication middleware
- Token handling and validation
- Security best practices

## Understanding OAuth 2.0

### What is OAuth 2.0?

OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access the user account.

### Key Components

1. **Resource Owner**: The user who authorizes an application to access their account
2. **Client**: The application that wants to access the user's account
3. **Resource Server**: The server hosting the protected resources
4. **Authorization Server**: The server that authenticates the user and issues access tokens

### Authorization Code Flow

The Authorization Code flow is the most secure OAuth 2.0 flow for web applications:

1. **Authorization Request**: Client redirects user to authorization server
2. **User Authentication**: User authenticates with authorization server
3. **Authorization Grant**: Authorization server redirects back with authorization code
4. **Token Request**: Client exchanges authorization code for access token
5. **Access Protected Resource**: Client uses access token to access protected resources

```csharp
// ASP.NET Core OAuth 2.0 Configuration
services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "OAuth2";
})
.AddCookie()
.AddOAuth("OAuth2", options =>
{
    options.ClientId = "your-client-id";
    options.ClientSecret = "your-client-secret";
    options.AuthorizationEndpoint = "https://provider.com/oauth/authorize";
    options.TokenEndpoint = "https://provider.com/oauth/token";
});
```

## Understanding OpenID Connect

### What is OpenID Connect?

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0. While OAuth 2.0 is designed for authorization, OpenID Connect adds authentication capabilities, allowing clients to verify the identity of users.

### Key Differences from OAuth 2.0

| OAuth 2.0 | OpenID Connect |
|-----------|----------------|
| Authorization framework | Authentication protocol |
| Access tokens | ID tokens + Access tokens |
| Resource access | User identity verification |
| No standard user info | Standardized user claims |

### ID Tokens

OpenID Connect introduces ID tokens, which are JSON Web Tokens (JWT) that contain user identity information:

```json
{
  "sub": "248289761001",
  "name": "Jane Doe",
  "email": "jane.doe@example.com",
  "iat": 1516239022,
  "exp": 1516242622,
  "aud": "your-client-id",
  "iss": "https://your-provider.com"
}
```

### Standard Scopes

- `openid`: Required scope that indicates OIDC request
- `profile`: Access to user's profile information
- `email`: Access to user's email address
- `address`: Access to user's address information
- `phone`: Access to user's phone number

## Implementation in ASP.NET Core

### Basic Configuration

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = "https://your-identity-provider.com";
        options.ClientId = "your-client-id";
        options.ClientSecret = "your-client-secret";
        options.ResponseType = "code";
        options.SaveTokens = true;
        
        // Configure scopes
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
    });
}
```

### Middleware Configuration

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // Order is important!
    app.UseAuthentication();
    app.UseAuthorization();
    
    app.UseRouting();
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```

### Authentication Controller

```csharp
[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    [HttpGet("login")]
    public IActionResult Login(string returnUrl = "/")
    {
        return Challenge(new AuthenticationProperties
        {
            RedirectUri = returnUrl
        });
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        return Redirect("/");
    }
}
```

### Accessing User Information

```csharp
[Authorize]
public class ProfileController : ControllerBase
{
    [HttpGet]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst("sub")?.Value;
        var userName = User.FindFirst("name")?.Value;
        var email = User.FindFirst("email")?.Value;
        
        return Ok(new
        {
            Id = userId,
            Name = userName,
            Email = email,
            Claims = User.Claims.Select(c => new { c.Type, c.Value })
        });
    }
}
```

### Token Management

```csharp
[Authorize]
public class TokenController : ControllerBase
{
    [HttpGet("access-token")]
    public async Task<IActionResult> GetAccessToken()
    {
        var accessToken = await HttpContext.GetTokenAsync("access_token");
        var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
        var idToken = await HttpContext.GetTokenAsync("id_token");
        
        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            IdToken = idToken
        });
    }
}
```

## Security Best Practices

### 1. Use HTTPS Everywhere

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddHttpsRedirection(options =>
    {
        options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
        options.HttpsPort = 443;
    });
}
```

### 2. Validate Tokens Properly

```csharp
services.AddOpenIdConnect(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.FromMinutes(5)
    };
});
```

### 3. Implement PKCE (Proof Key for Code Exchange)

```csharp
services.AddOpenIdConnect(options =>
{
    options.UsePkce = true; // Enabled by default in .NET 6+
});
```

### 4. Configure Secure Cookies

```csharp
services.AddCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    options.SlidingExpiration = true;
});
```

### 5. Handle Token Refresh

```csharp
services.AddOpenIdConnect(options =>
{
    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = async context =>
        {
            // Store tokens securely
            var tokens = context.Properties.GetTokens();
            // Implement token refresh logic
        }
    };
});
```

## Advanced Scenarios

### Custom Claims Transformation

```csharp
public class CustomClaimsTransformation : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = (ClaimsIdentity)principal.Identity;
        
        // Add custom claims
        if (principal.HasClaim("email", "admin@company.com"))
        {
            identity.AddClaim(new Claim("role", "Administrator"));
        }
        
        return Task.FromResult(principal);
    }
}

// Register the transformation
services.AddTransient<IClaimsTransformation, CustomClaimsTransformation>();
```

### Multiple Identity Providers

```csharp
services.AddAuthentication()
    .AddOpenIdConnect("Google", options =>
    {
        options.Authority = "https://accounts.google.com";
        options.ClientId = "google-client-id";
        options.ClientSecret = "google-client-secret";
    })
    .AddOpenIdConnect("Microsoft", options =>
    {
        options.Authority = "https://login.microsoftonline.com/common/v2.0";
        options.ClientId = "microsoft-client-id";
        options.ClientSecret = "microsoft-client-secret";
    });
```

### API Protection with JWT Bearer

```csharp
services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://your-identity-server.com";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });

services.AddAuthorization(options =>
{
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "api1");
    });
});
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Redirect URI Mismatch
**Problem**: `redirect_uri_mismatch` error
**Solution**: Ensure redirect URIs match exactly in both client and server configuration

```csharp
options.CallbackPath = "/signin-oidc"; // Must match registered URI
```

#### 2. Token Validation Failures
**Problem**: Token signature validation fails
**Solution**: Verify issuer and audience configuration

```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidIssuer = "https://your-identity-server.com",
    ValidAudience = "your-client-id"
};
```

#### 3. CORS Issues
**Problem**: Cross-origin requests blocked
**Solution**: Configure CORS properly

```csharp
services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin", builder =>
    {
        builder.WithOrigins("https://your-client-app.com")
               .AllowAnyMethod()
               .AllowAnyHeader()
               .AllowCredentials();
    });
});
```

#### 4. Cookie Size Limitations
**Problem**: Cookies too large for headers
**Solution**: Use session storage or external token store

```csharp
services.AddSession();
services.AddOpenIdConnect(options =>
{
    options.SaveTokens = false; // Don't save in cookies
    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = context =>
        {
            // Store tokens in session instead
            context.HttpContext.Session.SetString("access_token", 
                context.TokenEndpointResponse.AccessToken);
            return Task.CompletedTask;
        }
    };
});
```

### Debugging Tips

1. **Enable Detailed Logging**:
```csharp
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);
```

2. **Inspect Claims**:
```csharp
[HttpGet("debug")]
public IActionResult Debug()
{
    return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
}
```

3. **Validate Configuration**:
```csharp
services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Validate configuration at startup
    if (string.IsNullOrEmpty(options.ClientId))
        throw new InvalidOperationException("ClientId is required");
});
```

## Conclusion

OAuth 2.0 and OpenID Connect provide robust, standardized approaches to authentication and authorization in modern web applications. ASP.NET Core's built-in support makes implementation straightforward while maintaining security best practices.

Key takeaways:
- Use OpenID Connect for authentication, OAuth 2.0 for authorization
- Always use HTTPS in production
- Implement proper token validation and refresh logic
- Follow security best practices for cookie and session management
- Test thoroughly with different identity providers

This foundation will enable you to build secure, scalable authentication systems that integrate with various identity providers and protect your application resources effectively.