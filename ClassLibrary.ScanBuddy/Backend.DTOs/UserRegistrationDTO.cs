using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Backend.DTOs
{
    public class UserRegistrationDTO
    {

        public string FullName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }


        public string Role { get; set; } = "Employee"; // Default role is Employee, can be changed to Admin or SuperAdmin during registration
        public bool EnableMfa { get; set; } = false; //enable Mfa at registartion

    }
}
