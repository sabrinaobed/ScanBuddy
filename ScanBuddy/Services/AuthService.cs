using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ClassLibrary.ScanBuddy.Backend.DTOs;
using Microsoft.EntityFrameworkCore;
using ScanBuddy.Context;
using BCrypt.Net;
using System.ComponentModel.DataAnnotations;
using ScanBuddy.Models;


namespace ScanBuddy.Services
{
    public class AuthService : IAuthService
    {
        //depenendency injection of the ApplicationDbContext to interact with the database
        private readonly ApplicationDbContext _context;

        //Constructor that accepts ApplicationDbContext as a parameter
        public AuthService(ApplicationDbContext context)
        {
            _context = context;
        }

        //Method to register a new user
        public async Task<string> RegisterAsync(UserRegistrationDTO dto)
        {
            //1. input validation  - required fields check
            if(string.IsNullOrWhiteSpace(dto.FullName) ||
               string.IsNullOrWhiteSpace(dto.Email) ||
               string.IsNullOrWhiteSpace(dto.Password) ||
                string.IsNullOrWhiteSpace(dto.ConfirmPassword))
            {
                return "All field are required.";
            }


            //2.Validate email format
            if(!new EmailAddressAttribute().IsValid(dto.Email))
            {
                return "Invalid email format.";
            }

            //3.Check if email is already registered (case-insensitive)
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == dto.Email.ToLower());
            if(existingUser != null)
            {
                //optional: you could return a generic message to avoid enumeration
                return "Invalid credentials.Try again valid details."
            }

            //4.Check password match
            if(dto.Password != dto.ConfirmPassword)
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

            //7.Create a new ApplicationUser object
            var newUser = new ApplicationUser
            {
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Role = dto.Role ?? "Employee", //default role if not provided
                isMfaEnabled = false, //default MFA setting
                FailedLoginAttempts = 0, //default failed attempts
                LockedUntil = null, //default locked status
                CreatedAt = DateTime.UtcNow //set creation time to now,audit creation timestamp

            };


            //8.Add user to the database and save
            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();


            //9.Return success message(dont return sensitive data)
            return " User regisetered successfully! Now you login to your account.";

        }


    }
}

