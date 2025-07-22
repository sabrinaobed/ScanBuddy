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
using System.Text.Json;




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
                return "All fields are required.";
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


            //10.Send OTP
            string subject = "ScanBuddy Registration - Verify Your Email";
            string body = $"Hello {newUser.FullName}!,\n\n"+
                $"Your OTP code is: {otp}\n\n" +
                $"It is valid for 5 minutes.\n\n" +
                $"Thanks,\nScanBuddy Team";


           await _emailService.SendEmailAsync(newUser.Email, subject, body);


            //9.Return success message(dont return sensitive data)
            return "Verify your email through the OTP code sent at your email.";

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
                return "Invalid email or password.";
            }

            if(!user.HasVerifiedOtp)
            {
                return "Please verify your OTP before logging in.Check your registred email for OTP";
            }

            //5.Reset failed login attempts and lockout
            user.FailedLoginAttempts = 0;
            user.LockedUntil = null;
            await _context.SaveChangesAsync();


            //6.Generate a random OTP for MFA
            if(user.enableMFA == true)
            {
                //Mfa is enabled, generate OTP and send
                var otpCode = new Random().Next(100000, 999999).ToString();
                user.MfaCode = otpCode; //store OTP in user model
                user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(2); //set expiry time for OTP
                await _context.SaveChangesAsync(); //save changes to DB

                await _emailService.SendEmailAsync(user.Email, "Your ScanBuddy MFA Code", $"Your OTP code is: {otpCode}. It is valid for 2 minutes.");

                return $"MFA is enabled.OTP code sent to your registered email. Please verify to complete login.";
            }
            else
            {
                //MFA is n ot enabled: proceed to login and return JWT
                string token = GenerateJwtToken(user); //generate JWT token
                return token; //return the JWT token
            }

               
        }




        public async Task<LoginOtpVerificationResultDTO> VerifyLoginOtpAsync(UserOtpDTO dto)
        {
            var response = new LoginOtpVerificationResultDTO();

            if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.OtpCode))
            {
                response.Message = "Email and OTP code are required";
                return response;
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (user == null)
            {
                response.Message = "Invalid email or OTP code";
                return response;
            }

            if (!user.enableMFA)
            {
                response.Message = "MFA is not enabled for this account";
                return response;
            }

            if (user.MfaCode != dto.OtpCode)
            {
                response.Message = "Incorrect OTP code.";
                return response;
            }

            if (!user.MfaCodeExpiry.HasValue || user.MfaCodeExpiry < DateTime.UtcNow)
            {
                response.Message = "OTP code has expired. Please request a new one.";
                return response;
            }

            // OTP valid
            user.HasVerifiedOtp = true;
            user.MfaCode = null;
            user.MfaCodeExpiry = null;
            await _context.SaveChangesAsync();

            if (user.Role.Equals("admin", StringComparison.OrdinalIgnoreCase) ||
                user.Role.Equals("accountant", StringComparison.OrdinalIgnoreCase))
            {
                response.Token = GenerateJwtToken(user);
                response.Message = "OTP verified successfully. To get authorization dashobard enter the token sent to you.";
            }
            else
            {
                response.Message = "OTP verified successfully. Login complete.";
            }

            return response;
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

            // 4. Determine the purpose and set OTP & expiry
            if (!user.HasVerifiedOtp)
            {
                // It's for email verification
                user.MfaCode = newOtp;
                user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(5);

                await _context.SaveChangesAsync();

                await _emailService.SendEmailAsync(
                    user.Email,
                    "ScanBuddy Email Verification - OTP Code",
                    $"Hello {user.FullName},\n\nYour email verification OTP is: {newOtp}.\nIt is valid for 5 minutes.\n\nThanks,\nScanBuddy Team"
                );

                return "A new email verification OTP has been sent to your inbox.";

            }
            if (!user.enableMFA)
            {
                return "MFA is not enabled for this account.";
            }

            // If user is verified and MFA is enabled, send MFA code
            user.MfaCode = newOtp;
            user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(2);

            await _context.SaveChangesAsync();

            await _emailService.SendEmailAsync(
                user.Email,
                "Your new ScanBuddy MFA Code",
                $"Your new OTP code is: {newOtp}. It is valid for 2 minutes."
            );

            return "A new MFA OTP code has been sent to your email.";
        }




        //Method to check if the user has verified their OTP
        public async Task<bool> HasVerifiedOtpAsync(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                throw new Exception("User not found.");

            return user.HasVerifiedOtp;
        }


       
        public async Task<string> VerifyRegistrationOtpAsync(UserOtpDTO dto)
        {
            var user = await _context.Users
                 .FirstOrDefaultAsync(u => u.MfaCode == dto.OtpCode && !u.HasVerifiedOtp);

            if (user == null)
                return "Invalid OTP or already verified.";

            if (!user.MfaCodeExpiry.HasValue || user.MfaCodeExpiry < DateTime.UtcNow)
                return "OTP has expired.";

            user.HasVerifiedOtp = true;
            user.MfaCode = null;
            user.MfaCodeExpiry = null;

            await _context.SaveChangesAsync();

            return "Your email has been verified. You’re now registered at ScanBuddy.";
        }


        //Request Password Reset
        public async Task<string> RequestPasswordResetAsync(PasswordResetRequestDTO dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (user == null)
                return "User not found.";

            var token = Guid.NewGuid().ToString();
            user.PasswordResetToken = token;
            user.PasswordResetTokenExpiry = DateTime.UtcNow.AddMinutes(15);
            await _context.SaveChangesAsync();

            var resetLink = $"https://yourfrontend.com/reset-password?email={dto.Email}&token={token}";
            await _emailService.SendEmailAsync(dto.Email, "Reset your password", $"Click here: {resetLink}");

            return "Reset link has been sent to your email.";
        }



        //Confirm Password Reset
        public async Task<string> ConfirmPasswordResetAsync(PasswordResetConfirmDTO dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (user == null)
                return "Invalid request.";

            if (user.PasswordResetToken != dto.Token || user.PasswordResetTokenExpiry < DateTime.UtcNow)
                return "Invalid or expired token.";

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiry = null;
            await _context.SaveChangesAsync();

            return "Password has been successfully reset.";
        }


    }

}


