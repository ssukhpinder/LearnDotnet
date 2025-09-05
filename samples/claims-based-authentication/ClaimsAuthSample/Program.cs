using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
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

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireClaim("role", "admin"));
    options.AddPolicy("ManagerOrAdmin", policy => policy.RequireClaim("role", "manager", "admin"));
    options.AddPolicy("MinimumAge", policy => policy.RequireAssertion(context =>
        context.User.HasClaim("age", c => int.Parse(c) >= 18)));
    options.AddPolicy("DepartmentAccess", policy => policy.RequireClaim("department"));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", async (HttpContext context, string username, string role = "user", int age = 25, string department = "IT") =>
{
    var claims = new List<Claim>
    {
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

app.MapGet("/profile", (ClaimsPrincipal user) =>
{
    if (!user.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();

    var claims = user.Claims.Select(c => new { c.Type, c.Value });
    return Results.Ok(new { username = user.Identity.Name, claims });
}).RequireAuthorization();

app.MapGet("/admin", () => Results.Ok(new { message = "Admin access granted" }))
    .RequireAuthorization("AdminOnly");

app.MapGet("/manager", () => Results.Ok(new { message = "Manager or Admin access granted" }))
    .RequireAuthorization("ManagerOrAdmin");

app.MapGet("/adult-only", () => Results.Ok(new { message = "Adult content access granted" }))
    .RequireAuthorization("MinimumAge");

app.MapControllers();
app.Run();