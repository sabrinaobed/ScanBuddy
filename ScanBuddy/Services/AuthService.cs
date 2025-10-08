using ClassLibrary.ScanBuddy.Backend.DTOs;
using ClassLibrary.ScanBuddy.Backend.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ScanBuddy.Context;
using ScanBuddy.JWTConfiguration;
using ScanBuddy.Models;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ScanBuddy.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly JwtSettings _jwtSettings;
        private readonly IEmailService _emailService;

        public AuthService(ApplicationDbContext context, IOptions<JwtSettings> jwtoptions, IEmailService emailService)
        {
            _context = context;
            _jwtSettings = jwtoptions.Value;
            _emailService = emailService;
        }









        // ---------------- Registration ----------------

        public async Task<string> RegisterAsync(UserRegistrationDTO dto)
        {
            // 1) Basic validation
            if (string.IsNullOrWhiteSpace(dto.FullName) ||
                string.IsNullOrWhiteSpace(dto.Email) ||
                string.IsNullOrWhiteSpace(dto.Password) ||
                string.IsNullOrWhiteSpace(dto.ConfirmPassword))
                return "All fields are required.";

            // 2) Email format
            if (!new EmailAddressAttribute().IsValid(dto.Email))
                return "Invalid email format.";

            // 3) Uniqueness (case-insensitive)
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (existingUser != null)
                return "Invalid credentials.Try again valid details.";

            // 4) Passwords match
            if (dto.Password != dto.ConfirmPassword)
                return "Passwords do not match.";

            // 5) Password strength
            if (dto.Password.Length < 8 ||
                !dto.Password.Any(char.IsUpper) ||
                !dto.Password.Any(char.IsLower) ||
                !dto.Password.Any(char.IsDigit) ||
                !dto.Password.Any(ch => "!@#$%&*()_+-=[]{}|;:',.<>/?".Contains(ch)))
                return " Password must be at least 8 characters long and include uppercase, lowercase,digit and special characters.";

            // 6) Hash
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            // 7) Registration OTP
            var otp = new Random().Next(100000, 999999).ToString();
            var otpExpiry = DateTime.UtcNow.AddMinutes(5);

            // 8) Create user
            // [CHANGE] lock role to a safe default; do NOT trust client-sent role
            var newUser = new ApplicationUser
            {
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Role = "Employee",                    // <-- SAFE DEFAULT
                enableMFA = dto.EnableMfa,           // default MFA setting
                AccountType = dto.AccountType ?? "Personal",
                FailedLoginAttempts = 0,
                LockedUntil = null,
                CreatedAt = DateTime.UtcNow,
                MfaCode = otp,
                MfaCodeExpiry = otpExpiry,
                HasVerifiedOtp = false
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            // 9) Send verification email
            var subject = "ScanBuddy Registration - Verify Your Email";
            var body =
                $"Hello {newUser.FullName}!,\n\n" +
                $"Your OTP code is: {otp}\n\n" +
                $"It is valid for 5 minutes.\n\n" +
                $"Thanks,\nScanBuddy Team";

            // [CHANGE] wrap email send in try/catch so we never 500
            try
            {
                await _emailService.SendEmailAsync(newUser.Email, subject, body);
            }
            catch (Exception ex)
            {
                // Keep the user; they can use "resend-otp".
                return $"Registered, but failed to send verification email: {ex.Message}";
            }

            return "Verify your email through the OTP code sent at your email.";
        }












        // ---------------- Login / MFA ----------------

        public async Task<string> LoginAsync(UserLoginDTO dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
                return "Email and password are required.";

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if (user == null)
                return "Invalid email or password.";

            // lockout
            if (user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
                return $"Account is locked.Try again at {user.LockedUntil.Value}";

            // verify password
            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash);
            if (!isPasswordValid)
            {
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= 5)
                {
                    user.LockedUntil = DateTime.UtcNow.AddSeconds(60);
                    await _context.SaveChangesAsync();
                    return "Too many failed attempts.Account locked for 60 seconds.";
                }

                await _context.SaveChangesAsync();
                return "Invalid email or password.";
            }

            if (!user.HasVerifiedOtp)
                return "Please verify your OTP before logging in.Check your registred email for OTP";

            user.FailedLoginAttempts = 0;
            user.LockedUntil = null;
            await _context.SaveChangesAsync();

            // MFA flow
            if (user.enableMFA)
            {
                var otpCode = new Random().Next(100000, 999999).ToString();
                user.MfaCode = otpCode;
                user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(2);
                await _context.SaveChangesAsync();

                // [CHANGE] wrap in try/catch
                try
                {
                    await _emailService.SendEmailAsync(
                        user.Email,
                        "Your ScanBuddy MFA Code",
                        $"Your OTP code is: {otpCode}. It is valid for 2 minutes.");
                }
                catch (Exception ex)
                {
                    return $"Failed to send MFA code: {ex.Message}";
                }

                return "MFA is enabled.OTP code sent to your registered email. Please verify to complete login.";
            }

            // No MFA → return JWT
            string token = GenerateJwtToken(user);
            return token;
        }



        // ---------------- Verify Login OTP ----------------
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

            // [CHANGE] Do NOT set HasVerifiedOtp here (that flag is for email verification)
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




        // ---------------- Resend OTP ----------------

        public async Task<string> ResendOtpAysnc(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return "Email is required.";

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == email.ToLower());
            if (user == null) return "Invalid email. User not found.";

            var newOtp = new Random().Next(100000, 999999).ToString();

            // [CHANGE] 1) Registration verification case first
            if (!user.HasVerifiedOtp)
            {
                user.MfaCode = newOtp;
                user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(5);
                await _context.SaveChangesAsync();

                try
                {
                    await _emailService.SendEmailAsync(
                        user.Email,
                        "ScanBuddy Email Verification - OTP Code",
                        $"Hello {user.FullName},\n\nYour email verification OTP is: {newOtp}.\nIt is valid for 5 minutes.\n\nThanks,\nScanBuddy Team");
                }
                catch (Exception ex)
                {
                    return $"Failed to send verification OTP email: {ex.Message}";
                }

                return "A new email verification OTP has been sent to your inbox.";
            }

            // [CHANGE] 2) MFA case second (only if account already verified)
            if (!user.enableMFA)
                return "MFA is not enabled for this account.";

            user.MfaCode = newOtp;
            user.MfaCodeExpiry = DateTime.UtcNow.AddMinutes(2);
            await _context.SaveChangesAsync();

            try
            {
                await _emailService.SendEmailAsync(
                    user.Email,
                    "Your new ScanBuddy MFA Code",
                    $"Your new OTP code is: {newOtp}. It is valid for 2 minutes.");
            }
            catch (Exception ex)
            {
                return $"Failed to send MFA OTP email: {ex.Message}";
            }

            return "A new MFA OTP code has been sent to your email.";
        }












        // ---------------- Utilities ----------------

        public async Task<bool> HasVerifiedOtpAsync(string email)
        {
            // [CHANGE] return false if user not found; do not throw
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            return user?.HasVerifiedOtp ?? false;
        }


        // ---------------- Verify Registration OTP ----------------
        public async Task<string> VerifyRegistrationOtpAsync(UserOtpDTO dto)
        {
            // [CHANGE] Validate by Email + OTP, not OTP-only
            if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.OtpCode))
                return "Email and OTP are required.";

            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.Email.ToLower() == dto.Email.ToLower() &&
                u.MfaCode == dto.OtpCode &&
                !u.HasVerifiedOtp);

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




        // ---------------- Password Reset ----------------
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

            // [CHANGE] wrap email send
            try
            {
                await _emailService.SendEmailAsync(dto.Email, "Reset your password", $"Click here: {resetLink}");
            }
            catch (Exception ex)
            {
                return $"Failed to send password reset email: {ex.Message}";
            }

            return "Reset link has been sent to your email.";
        }


        // ---------------- Confirm Password Reset ----------------

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













        // ---------------- JWT ----------------

        private string GenerateJwtToken(ApplicationUser user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Email,          user.Email),
                new Claim(ClaimTypes.Name,           user.FullName),
                new Claim(ClaimTypes.Role,           user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
