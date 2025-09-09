using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore; // Required for UseSqlServer
using ScanBuddy.Context; // Make sure this is the correct namespace for ApplicationDbContext
using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ScanBuddy.Services;

var builder = WebApplication.CreateBuilder(args);

// Register ApplicationDbContext with SQL Server connection string
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    // Make sure "DefaultConnection" exists in appsettings.json
});

// Register controllers
builder.Services.AddControllers();

// Register your AuthService for dependency injection
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();


// Register Swagger for API documentation/testing
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure CORS to allow Blazor frontend (running at https://localhost:7181)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(
            "https://localhost:7181", // HTTPS Blazor frontend
            "http://localhost:7181"   // HTTP fallback for dev
        )
        .AllowAnyHeader()
        .AllowAnyMethod();
    });
});

var app = builder.Build();

// Enable Swagger UI in development mode
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Redirect all HTTP requests to HTTPS
app.UseHttpsRedirection();

// Use the defined CORS policy before handling any request
app.UseCors("AllowFrontend");

// Enable authorization (if any [Authorize] attributes exist)
app.UseAuthorization();

// Map controller endpoints
app.MapControllers();

// Run the application
app.Run();
