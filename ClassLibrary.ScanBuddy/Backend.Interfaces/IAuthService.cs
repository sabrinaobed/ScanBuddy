using ClassLibrary.ScanBuddy.Backend.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Backend.Interfaces
{
    internal interface IAuthService
    {
        Task<string> RegisterAsync(UserRegistrationDTO dto);
        Task<string>LoginAsync(UserLoginDTO dto);
    }
}
