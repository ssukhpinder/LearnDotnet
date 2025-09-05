using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using PolicyAuthSample.Authorization;
using PolicyAuthSample.Models;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
    });

// Register authorization handlers
builder.Services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();
builder.Services.AddScoped<IAuthorizationHandler, DepartmentHandler>();
builder.Services.AddScoped<IAuthorizationHandler, ResourceOwnerHandler>();
builder.Services.AddScoped<IAuthorizationHandler, BusinessHoursHandler>();

builder.Services.AddAuthorization(options =>
{
    // Simple policy with single requirement
    options.AddPolicy("Adult", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
    
    // Policy with multiple requirements (AND logic)
    options.AddPolicy("SeniorEmployee", policy =>
    {
        policy.Requirements.Add(new MinimumAgeRequirement(25));
        policy.Requirements.Add(new DepartmentRequirement("Management", "HR"));
    });
    
    // Complex policy combining requirements and claims
    options.AddPolicy("FinanceAccess", policy =>
    {
        policy.RequireClaim("role", "manager", "admin");
        policy.Requirements.Add(new DepartmentRequirement("Finance", "Accounting"));
        policy.Requirements.Add(new BusinessHoursRequirement(
            new TimeSpan(9, 0, 0), new TimeSpan(17, 0, 0)));
    });
    
    // Resource-based policy
    options.AddPolicy("ResourceOwner", policy =>
        policy.Requirements.Add(new ResourceOwnerRequirement()));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

// Sample documents for demonstration
var documents = new List<Document>
{
    new() { Id = 1, Title = "Public Document", Content = "Public content", OwnerId = "user1", IsConfidential = false },
    new() { Id = 2, Title = "Private Document", Content = "Private content", OwnerId = "user1", IsConfidential = true },
    new() { Id = 3, Title = "Admin Document", Content = "Admin content", OwnerId = "admin", IsConfidential = true }
};

app.MapPost("/login", async (HttpContext context, string username, string role = "user", 
    int age = 25, string department = "IT") =>
{
    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, username),
        new(ClaimTypes.Name, username),
        new("role", role),
        new("age", age.ToString()),
        new("department", department)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
    return Results.Ok(new { message = "Logged in successfully", claims = claims.Select(c => new { c.Type, c.Value }) });
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { message = "Logged out successfully" });
});

app.MapGet("/adult-content", () => Results.Ok(new { message = "Adult content accessed" }))
    .RequireAuthorization("Adult");

app.MapGet("/senior-employee", () => Results.Ok(new { message = "Senior employee area accessed" }))
    .RequireAuthorization("SeniorEmployee");

app.MapGet("/finance", () => Results.Ok(new { message = "Finance data accessed", time = DateTime.Now }))
    .RequireAuthorization("FinanceAccess");

app.MapGet("/documents", (ClaimsPrincipal user) =>
{
    if (!user.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();
    
    return Results.Ok(documents.Select(d => new { d.Id, d.Title, d.OwnerId, d.IsConfidential }));
}).RequireAuthorization();

app.MapGet("/documents/{id:int}", async (int id, IAuthorizationService authService, ClaimsPrincipal user) =>
{
    var document = documents.FirstOrDefault(d => d.Id == id);
    if (document == null)
        return Results.NotFound();

    // Check if user owns the resource
    var authResult = await authService.AuthorizeAsync(user, document.OwnerId, "ResourceOwner");
    
    if (!authResult.Succeeded)
        return Results.Forbid();

    return Results.Ok(document);
});

app.MapControllers();
app.Run();