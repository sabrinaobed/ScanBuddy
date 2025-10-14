using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Frontend.DTOs
{
    public class ApiResponse
    {
        public bool Success { get; set; } // backend now returns { success, message, token? }
        public string Message { get; set; } = "";
        public string? Token { get; set; } // present for login and verify-login-otp when JWT issued
    }
}
