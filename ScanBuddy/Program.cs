using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ScanBuddy.JWTConfiguration;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ScanBuddy.Context;
using Microsoft.OpenApi.Models;
using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ScanBuddy.Services;









namespace ScanBuddy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            //controllers
            builder.Services.AddControllers();
            //CORS -keep this aligned with actual frontend origin
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowFrontend",
                    policy =>
                    {
                        policy.WithOrigins("http://localhost:4200") // your frontend URL
                              .AllowAnyHeader()
                              .AllowAnyMethod();
                        //.AllowCredentials(); // if you need to allow cookies or authentication
                    });
            });


            //APP SERVICES
            // Add services to the container.
            // Register services
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IEmailService, EmailService>();


            //EF CORE -  SQL SERVER
            // Register EF Core with SQL server
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            //SWAGGER/OPENAPI
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "ScanBuddy API",
                    Version = "v1"
                });

                // Add JWT Authentication to Swagger
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme (Example: 'Bearer eyJhbGciOi...')",
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


            // Bind JwtSettings from appsettings.json
            builder.Services.Configure<JwtSettings>(
                builder.Configuration.GetSection("JwtSettings"));

            //Read and validate jwt settings early so failures are caught during startup
            var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()
             ?? throw new InvalidOperationException("JwtSettings section is missing in configuration.");

            if(string.IsNullOrEmpty(jwtSettings.SecretKey))
                throw new InvalidOperationException("JWT SecretKey is not configured or misisng.");
            if (string.IsNullOrEmpty(jwtSettings.Issuer))
                throw new InvalidOperationException("JWT Issuer is not configured or missing/empty.");
            if(string.IsNullOrEmpty(jwtSettings.Audience))
                throw new InvalidOperationException("JWT Audience is not configured or missing/empty.");

            // Configure JWT Authentication
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

                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(jwtSettings.SecretKey))
                };
            });

            // Bind SmtpSettings from appsettings.json
            builder.Services.Configure<SmtpSettings>(
                builder.Configuration.GetSection("Smtp"));


            var app = builder.Build();

            // Apply EF migrations automatically at startup (dev-friendly)
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                db.Database.Migrate(); // Will create/update DB schema to latest migration
            }

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "ScanBuddy API v1");
                });
            }


            //Standard middleware order
            app.UseHttpsRedirection();
            app.UseRouting();

            app.UseCors("AllowFrontend");

            app.UseAuthentication();//must be vefore authorization
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
