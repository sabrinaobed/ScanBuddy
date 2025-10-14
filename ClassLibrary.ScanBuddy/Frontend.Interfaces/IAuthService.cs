using System.Threading.Tasks;
using ClassLibrary.ScanBuddy.Frontend.DTOs;   // ApiResponse + Frontend DTOs (RegistrationDTO, LoginDTO, etc.)
using ClassLibrary.ScanBuddy.Backend.DTOs;    // PasswordReset* DTOs if they live under Backend.DTOs

namespace ClassLibrary.ScanBuddy.Frontend.Interfaces
{
    /// <summary>
    /// Client-side auth service interface for the Blazor app.
    /// All API calls return a unified ApiResponse { Success, Message, Token? }.
    /// </summary>
    public interface IAuthService
    {
        Task<ApiResponse> RegisterAsync(RegistrationDTO dto);
        Task<ApiResponse> VerifyRegistrationOtpAsync(VerifyRegistrationOtpDTO dto);

        Task<ApiResponse> LoginAsync(LoginDTO dto);
        Task<ApiResponse> VerifyLoginOtpAsync(VerifyLoginOtpDTO dto);

        // Body is { "email": "<address>" } per the backend controller
        Task<ApiResponse> ResendOtpAsync(string email);

        // Utility endpoint returns { isVerified } on the wire; client returns bool
        Task<bool> HasVerifiedOtpAsync(string email);

        Task<ApiResponse> RequestPasswordResetAsync(PasswordResetRequestDTO dto);
        Task<ApiResponse> ConfirmPasswordResetAsync(PasswordResetConfirmDTO dto);
    }
}
