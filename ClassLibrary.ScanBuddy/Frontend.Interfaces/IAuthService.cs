using ClassLibrary.ScanBuddy.Frontend.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Frontend.Interfaces
{
    public  interface IAuthService
    {
        Task<string> RegisterAsync(RegistrationDTO dto);

        Task<string> VerifyRegistrationOtpAsync(VerifyRegistrationOtpDTO dto);

        Task<string> LoginAsync(LoginDTO dto);

        Task<string> VerifyLoginOtpAsync(VerifyLoginOtpDTO dto);
    }
}
