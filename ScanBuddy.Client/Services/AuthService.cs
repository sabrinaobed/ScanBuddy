using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using ClassLibrary.ScanBuddy.Frontend.DTOs;
using ClassLibrary.ScanBuddy.Frontend.Interfaces;

namespace ScanBuddy.Client.Services
{
    public class AuthService : IAuthService
    {
        private readonly HttpClient _http;

        public AuthService(HttpClient http)
        {
            _http = http;
        }

        public async Task<ApiResponse> RegisterAsync(RegistrationDTO dto)
        {
            var response = await _http.PostAsJsonAsync("auth/register", dto);

            if (response.IsSuccessStatusCode)
            {
                var apiResponse = await response.Content.ReadFromJsonAsync<ApiResponse>();
                return apiResponse!;
            }

            var error = await response.Content.ReadAsStringAsync();
            return new ApiResponse { Success = false, Message = error };
        }


        public async Task<ApiResponse> VerifyRegistrationOtpAsync(VerifyRegistrationOtpDTO dto)
        {
            var response = await _http.PostAsJsonAsync("auth/verify-registration-otp", dto);

            if (response.IsSuccessStatusCode)
            {
                var apiResponse = await response.Content.ReadFromJsonAsync<ApiResponse>();
                return apiResponse!;
            }

            var error = await response.Content.ReadAsStringAsync();
            return new ApiResponse { Success = false, Message = error };
        }


        public async Task<string> LoginAsync(LoginDTO dto)
        {
            var response = await _http.PostAsJsonAsync("auth/login", dto);
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> VerifyLoginOtpAsync(VerifyLoginOtpDTO dto)
        {
            var response = await _http.PostAsJsonAsync("auth/verify-login-otp", dto);
            return await response.Content.ReadAsStringAsync();
        }
    }

}
