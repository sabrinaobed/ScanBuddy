using Microsoft.AspNetCore.Authentication.JwtBearer; //Jwt Auth
using Microsoft.IdentityModel.Tokens; //Token validation
using Microsoft.OpenApi.Models; //Swagger
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore; // Required for UseSqlServer
using System.Text; // Required for Encoding




using ScanBuddy.Context; // Make sure this is the correct namespace for ApplicationDbContext
using ScanBuddy.JWTConfiguration; //JwtSettings/SmtpSettings
using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ScanBuddy.Services;

var builder = WebApplication.CreateBuilder(args);


//--------Services Configuration--------//
//Controllers
builder.Services.AddControllers();


//CORS
//Allow the frontend origins  Blazor WASM dev server
//-https://localhost:7181 (HTTPS) and http://localhost:5001 (HTTP fallback for dev)
//Matches frontend launch settings in ScanBuddy.Client Properties/launchSettings.json
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(
            "https://localhost:7181", // HTTPS Blazor frontend
            "http://localhost:5001"
        )
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials(); // If you need to send cookies or auth headers
    });
});




//App Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();


//EF Core with SQL Server
// Register ApplicationDbContext with SQL Server connection string
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    // Make sure "DefaultConnection" exists in appsettings.json
});



//Swagger/OpenAPI + JWT auth header in Swagger UI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ScanBuddy API",
        Version = "v1",
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});


//Settings binding for JWT and SMTP
//Bind jwtsettings and smtpsettings sections of appsettings.json
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("Smtp"));


//Validate JwtSettings early to catch config errors at startup
var jwt = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()
     ?? throw new InvalidOperationException("JwtSettings section is missing");
if(string.IsNullOrWhiteSpace(jwt.SecretKey))
    throw new InvalidOperationException("JwtSettings:SecretKey is missing/empty");
if (string.IsNullOrWhiteSpace(jwt.Issuer))
    throw new InvalidOperationException("JwtSettings:Issuer is missing/empty");
if (string.IsNullOrWhiteSpace(jwt.Audience))
    throw new InvalidOperationException("JwtSettings:Audience is missing/empty");

//JWT Authentication pipeline
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SecretKey)),

        //add a small tolerance for clock drift
        ClockSkew = TimeSpan.FromSeconds(30) 
    };
});

var app = builder.Build();


//----------Middleware Pipeline Configuration----------//
if(!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

//HTTPS redirect 
app.UseHttpsRedirection();

//Routing -> CORS -> AuthN -> AuthZ
app.UseRouting();
app.UseCors("AllowFrontend");

app.UseAuthentication();//must be before UseAuthorization
app.UseAuthorization();

//Swagger only in dev mode
if(app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "ScanBuddy API v1");
    });
    
}

//Auto-apply EF migrations at start up-
//Remove if your deplment process handles migrations separately
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    db.Database.Migrate();
}
//Map controller 
app.MapControllers();

//Run
app.Run();





