using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Frontend.DTOs
{
 

        public class RegistrationDTO
        {
            public string FullName { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
            public string ConfirmPassword { get; set; }
            public string Role { get; set; } = "Employee";
            public bool EnableMfa { get; set; } = false;
            public string AccountType { get; set; } = "Personal";
        }
    }



