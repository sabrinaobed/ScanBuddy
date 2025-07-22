using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Backend.DTOs
{
    public class PasswordResetTokenDTO
    {
        public string Email { get; set; }
        public string Token { get; set; }
        public DateTime ExpiryTime { get; set; }
    }

}
