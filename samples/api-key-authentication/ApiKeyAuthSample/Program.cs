using ApiKeyAuthSample.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

var app = builder.Build();

app.UseMiddleware<ApiKeyMiddleware>();
app.MapControllers();

app.Run();