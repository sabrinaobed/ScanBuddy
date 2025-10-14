using ClassLibrary.ScanBuddy.Backend.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary.ScanBuddy.Backend.Interfaces
{
    public interface IAuthService
    {
        Task<string> RegisterAsync(UserRegistrationDTO dto);
        Task<string>LoginAsync(UserLoginDTO dto);

        Task<string> VerifyRegistrationOtpAsync(UserOtpDTO dto);

        Task<LoginOtpVerificationResultDTO> VerifyLoginOtpAsync(UserOtpDTO dto);

        Task<string> ResendOtpAsync(string email);

        Task<bool> HasVerifiedOtpAsync(string email);

        Task<string> RequestPasswordResetAsync(PasswordResetRequestDTO dto);
        Task<string> ConfirmPasswordResetAsync(PasswordResetConfirmDTO dto);



    }
}
