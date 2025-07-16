using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ClassLibrary.ScanBuddy.Backend.DTOs;
using Microsoft.EntityFrameworkCore;
using ScanBuddy.Context;
using BCrypt.Net;
using System.ComponentModel.DataAnnotations;
using ScanBuddy.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ScanBuddy.JWTConfiguration;
using Org.BouncyCastle.Crypto.Fpe; 




namespace ScanBuddy.Services
{
    public class AuthService : IAuthService
    {
        //depenendency injection of the ApplicationDbContext to interact with the database
        private readonly ApplicationDbContext _context;
        private readonly JwtSettings _jwtSettings;
        private readonly IEmailService _emailService; //dependency injection for email service to send OTPs and notifications


        //Constructor that accepts ApplicationDbContext as a parameter
        public AuthService(ApplicationDbContext context, IOptions<JwtSettings> jwtoptions, IEmailService emailService)
        {
            _context = context;
            _jwtSettings = jwtoptions.Value; //binds the JwtSettings from appsettings.json,contains secret key and issuer.
            _emailService = emailService; //injects the email service to send OTPs and notifications

        }

        //Method to register a new user
        public async Task<string> RegisterAsync(UserRegistrationDTO dto)
        {
            //1. input validation  - required fields check
            if (string.IsNullOrWhiteSpace(dto.FullName) ||
               string.IsNullOrWhiteSpace(dto.Email) ||
               string.IsNullOrWhiteSpace(dto.Password) ||
                string.IsNullOrWhiteSpace(dto.ConfirmPassword))
            {
                return "All field are required.";
            }


            //2.Validate email format
            if (!new EmailAddressAttribute().IsValid(dto.Email))
            {
                return "Invalid email format.";
            }

            //3.Check if email is already registered (case-insensitive)
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (existingUser != null)
            {
                //optional: you could return a generic message to avoid enumeration
                return "Invalid credentials.Try again valid details.";
            }

            //4.Check password match
            if (dto.Password != dto.ConfirmPassword)
            {
                return "Passwords do not match.";
            }

            //5.Validate password strength(OWASP recommendation: length + complexity)
            if (dto.Password.Length < 8 ||
               !dto.Password.Any(char.IsUpper) ||
               !dto.Password.Any(char.IsLower) ||
               !dto.Password.Any(char.IsDigit) ||
                !dto.Password.Any(ch => "!@#$%&*()_+-=[]{}|;:',.<></?".Contains(ch)))

            {
                return " Password must be at least 8 characters long and include uppercase, lowercase,digit and special characters.";
            }


            //6. Hash the password using BCrypt(never store plain passowrd)
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);


            //7.Generate OTP for email verification...
            var otp = new Random().Next(100000, 999999).ToString();
            var otpExpiry = DateTime.UtcNow.AddMinutes(5); //valid for 5 minutes

            //8.Create a new ApplicationUser object.
            var newUser = new ApplicationUser
            {
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Role = dto.Role ?? "Employee", //default role if not provided
                enableMFA = dto.EnableMfa, //default MFA setting
                AccountType = dto.AccountType ?? "Personal", //default account type if not provided
                FailedLoginAttempts = 0, //default failed attempts
                LockedUntil = null, //default locked status
                CreatedAt = DateTime.UtcNow, //set creation time to now,audit creation timestamp
                MfaCode = otp, //set the OTP code
                MfaCodeExpiry = otpExpiry, //set the OTP expiry time
                HasVerifiedOtp = false //default to false, user needs to verify OTP after registration


            };


            //9.Add user to the database and save
            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();


            //10.Sed OTP
            string subject = "ScanBuddy Registration -Verify Your Email";
            string body = $"Hello! {newUser.FullName},\n\n"+
                $"Your OTP code is: {otp}\n\n" +
                $"It is valid for 5 minutes.\n\n" +
                $"Thanks,\nScanBuddy Team";


           // await _emailService.SendEmailAsync(newUser.Email, subject, body);


            //9.Return success message(dont return sensitive data)
            return " User regisetered successfully! Now you login to your account.";

        }


        public async Task<string> LoginAsync(UserLoginDTO dto)
        {
            //1. check required fields
            if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
            {
                return "Email and password are required.";
            }

            //2.Find user by email (case-insenstive)
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (user == null)
            {
                //generic message to avoid account enumeration
                return "Invalid email or password.";
            }

            //3.check if account is locked
            if (user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
            {
                return $"Account is locked.Try again at {user.LockedUntil.Value}";
            }

            //4.Check password usimh BCrypt
            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash);
            if (!isPasswordValid)
            {
                user.FailedLoginAttempts++;

                //optional: lock account after 5 failed attempts for 1 minute
                if (user.FailedLoginAttempts >= 5)
                {
                    user.LockedUntil = DateTime.UtcNow.AddSeconds(60);
                    await _context.SaveChangesAsync();
                    return "Too many failed attempts.Account locked for 60 seconds.";
                }
                await _context.SaveChangesAsync();
                return "Invalif email or password.";
            }

            //5.Reset failed login attempts and lockout
            user.FailedLoginAttempts = 0;
            user.LockedUntil = null;
            await _context.SaveChangesAsync();


            //6.Generate a random OTP for MFA
            var otpCode = new Random().Next(100000, 999999).ToString();

            //7.Store the OTP temporarily example in memory or DB
            //for now assume you add a property OTP and Expiry in ApplicationUser model
            user.MfaCode = otpCode;
            user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(2); // valif for a minute
            await _context.SaveChangesAsync();

            //8.Send the OTP to user's email(you will implement actual email services next)
            //await _emailService.SendEmailAsync(user.Email, "Your ScanBuddy MFA Code", $"Your OTP code is: {otpCode}.");

            //9.Return success message with MFA instructions
            return "MFA code sent to  {user.Email}. Please verify to complete login.";
        }


        public async Task<string> VerifyOtpAsync(UserOtpDTO dto)
        {
            //1. Validate input fields
            if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.OtpCode))
            {
                return "Email and OTP code are required";
            }

            //2.Find user by email (case-insensitive)
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());

            if (user == null)
            {
                return "Invalid email or OTP code";
            }

            //3.Check if MFA is enabled
            if(!user.enableMFA)
            {
                return "MFA is not enabled for this account";
            }

            //4.Check if OTP code matches and has not expired
            if (user.MfaCode != dto.OtpCode)
            {
                return "Incorrect OTP code.";
            }

            if (!user.MfaCodeExpiry.HasValue || user.MfaCodeExpiry < DateTime.UtcNow)
            {
                return "OTP code has expired. Please request a new one.";
            }

            //5.OTP is valif -> clear the OTP and expiry from DB
            user.MfaCode = null;
            user.MfaCodeExpiry = null;
            await _context.SaveChangesAsync();

            //6.Generate JWT token
            string token = GenerateJwtToken(user);


            //7. Return success message with token
            return token;
        }


        //Creates a JWT token containing user information
        private string GenerateJwtToken(ApplicationUser user)
        {
            //Create signing credentials
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //2.Create the list of claims(data baked into token)
            var claims = new[]
            {
                 new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
        new Claim(ClaimTypes.Email,          user.Email),
        new Claim(ClaimTypes.Name,           user.FullName),
        new Claim(ClaimTypes.Role,           user.Role)
            };

            //3.Build the token object
            var token = new JwtSecurityToken(
                 issuer: _jwtSettings.Issuer,
        audience: _jwtSettings.Audience,
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryMinutes),
        signingCredentials: creds);


            //4.Generate the token string
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<string> ResendOtpAysnc(string email)
        {
            // 1. Validate input
            if (string.IsNullOrWhiteSpace(email))
            {
                return "Email is required.";
            }

            // 2. Find the user by email
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == email.ToLower());
            if (user == null)
            {
                return "Invalid email. User not found.";
            }

            // 3. Check if MFA is enabled
            if (!user.enableMFA)
            {
                return "MFA is not enabled for this account.";
            }

            // 4. Generate a new OTP
            var newOtp = new Random().Next(100000, 999999).ToString();

            // 5. Store OTP and expiry
            user.MfaCode = newOtp;
            user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(2);
            await _context.SaveChangesAsync();

            // 6. Send OTP via email
            await _emailService.SendEmailAsync(
                user.Email,
                "Your new ScanBuddy OTP Code",
                $"Your new OTP code is: {newOtp}. It is valid for 2 minutes."
            );

            return "A new OTP code has been sent to your email.";
        }

        public async Task<bool> HasVerifiedOtpAsync(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                throw new Exception("User not found.");

            return user.HasVerifiedOtp;
        }



    }

}


