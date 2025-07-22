
using System;
using System.ComponentModel.DataAnnotations;

namespace ScanBuddy.Models
{
    public class ApplicationUser
    {
        [Key]
        public int UserId { get; set; } // primary key - uniquely identifies each user in the database

        [Required]
        public string FullName { get; set; } //Full Name of the user (used for display or identification)

        [Required]
        [EmailAddress]
        public string Email { get; set; } //Email is the unique identifier for Login, validated with an email format

        [Required]
        public  string PasswordHash { get; set; } //PasswordHash is the hashed version of the user's password for security purposes, this stores the Bcrpyt-hashed password

        [Required]  
        public string Role { get; set; } = "Employee"; //Role of the user(superadmin, admin , accountant, employee: used to control access to diffferent parts of the app)
        public bool enableMFA { get; set; } = false; // Whether the user has enabled Multi-Factor Authentication (MFA) for added security,if true they must verify a code after password login

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow; //Timestamp when the account was created, useful for audit logs or sortung users by creation date

        public int FailedLoginAttempts { get; set; } = 0; //number of failed login attempts, protect against brute-force attacks

        public DateTime? LockedUntil { get; set; } //the account locked until this time after failed login  attempts, used to temporarliy block users.

        public string? MfaCode { get; set; } //one-time code for MFA verfication, sent to user's email

        public DateTime? MfaCodeExpiry { get; set; } //expiration time for the MFA code 
        public bool HasVerifiedOtp { get; set; } = false;

        public string AccountType { get; set; } = "Personal"; //to select accoutn type

        public string? PasswordResetToken { get; set; }
        public DateTime? PasswordResetTokenExpiry { get; set; }

    }

}
