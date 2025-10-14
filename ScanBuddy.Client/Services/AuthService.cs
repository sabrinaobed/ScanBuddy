using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using ClassLibrary.ScanBuddy.Frontend.DTOs;
using ClassLibrary.ScanBuddy.Frontend.Interfaces;
using ClassLibrary.ScanBuddy.Backend.DTOs; // for password reset DTOs

namespace ScanBuddy.Client.Services
{
    /// <summary>
    /// Blazor WASM HttpClient-based implementation.
    /// Backend returns ApiResponse JSON for both 200 and 400; we always deserialize to ApiResponse.
    /// BaseAddress is configured as https://localhost:7025/api/ in Program.cs, so our paths start with "auth/...".
    /// </summary>
    public class AuthService : IAuthService
    {
        private readonly HttpClient _http;
        public AuthService(HttpClient http) => _http = http;

        public Task<ApiResponse> RegisterAsync(RegistrationDTO dto) =>
            Post<ApiResponse>("auth/register", dto);

        public Task<ApiResponse> VerifyRegistrationOtpAsync(VerifyRegistrationOtpDTO dto) =>
            Post<ApiResponse>("auth/verify-registration-otp", dto);

        public Task<ApiResponse> LoginAsync(LoginDTO dto) =>
            Post<ApiResponse>("auth/login", dto);

        public Task<ApiResponse> VerifyLoginOtpAsync(VerifyLoginOtpDTO dto) =>
            Post<ApiResponse>("auth/verify-login-otp", dto);

        // Body must be { "email": "..." } per backend controller
        public Task<ApiResponse> ResendOtpAsync(string email) =>
            Post<ApiResponse>("auth/resend-otp", new { email });

        public async Task<bool> HasVerifiedOtpAsync(string email)
        {
            // Backend returns { isVerified: bool }
            var result = await _http.GetFromJsonAsync<HasVerifiedDto>(
                $"auth/has-verified-otp?email={Uri.EscapeDataString(email)}");
            return result?.isVerified ?? false;
        }

        public Task<ApiResponse> RequestPasswordResetAsync(PasswordResetRequestDTO dto) =>
            Post<ApiResponse>("auth/request-password-reset", dto);

        public Task<ApiResponse> ConfirmPasswordResetAsync(PasswordResetConfirmDTO dto) =>
            Post<ApiResponse>("auth/confirm-password-reset", dto);

        // -------- helpers --------

        private async Task<T> Post<T>(string url, object body)
        {
            var res = await _http.PostAsJsonAsync(url, body);
            // Backend sends ApiResponse JSON even on 400; deserialize regardless of status.
            // If the body is empty or not JSON, throw to catch issues early.
            var payload = await res.Content.ReadFromJsonAsync<T>();
            if (payload == null) throw new InvalidOperationException("Empty/invalid API response.");
            return payload;
        }

        private record HasVerifiedDto(bool isVerified);
    }
}
