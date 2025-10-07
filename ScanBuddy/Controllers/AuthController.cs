using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ClassLibrary.ScanBuddy.Backend.DTOs;


namespace ScanBuddy.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        //Standarad response envelope so the frontend can deserialize consistently
        public record ApiResponse(bool Success, string Message, string? Token = null );

        //Small DTO to accept emial for resend otp endpoint than raw string
        public record ResendOtpDto(string Email);

        //--------Registration-------

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDTO dto)
        {
            var result = await _authService.RegisterAsync(dto);

            var ok = !(result.StartsWith("Invalid", System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("Error",   System.StringComparison.OrdinalIgnoreCase));

            var payload = new ApiResponse(ok, result);
            return ok? Ok(payload): BadRequest(payload);
        }




        //----------------Verify Registration OTP----------------
        /// Initiates registration and sends OTP to the user's email.
        

        [HttpPost("verify-registration-otp")]
        public async Task<IActionResult> VerifyRegistrationOtp([FromBody] UserOtpDTO dto)
        {
            var result = await _authService.VerifyRegistrationOtpAsync(dto);

            var ok = !(result.StartsWith("Invalid",        System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("Error",          System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("OTP has expired",System.StringComparison.OrdinalIgnoreCase));

            var payload =  new ApiResponse(ok, result);
            return ok ? Ok(payload) : BadRequest(payload);
        }






        //----------------Login with MFA----------------
        /// Initiates login and sends MFA code if credentials are valid.

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO dto)
        {
            var result = await _authService.LoginAsync(dto);

            //If MFA is OFF service returns a JWT else it returns a message
            bool lookLikeJwt = !string.IsNullOrWhiteSpace(result) && result.Split('.').Length == 3;
            if (lookLikeJwt)
                return Ok(new ApiResponse(true, "Login successful.", result));


            var ok = !(result.StartsWith("Invalid", System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("Error", System.StringComparison.OrdinalIgnoreCase));


            var payload = new ApiResponse(ok, result);
            return ok ? Ok(payload) : BadRequest(payload);

        }



        //----------------Verify Login OTP----------------
        /// Verifies the MFA code and returns a JWT token if successful.

        [HttpPost("verify-login-otp")]
     
        public async Task<IActionResult> VerifyLoginOtp([FromBody] UserOtpDTO dto)
        {

            // Service returns LoginOtpVerificationResultDTO { Message, Token? }
            var result = await _authService.VerifyLoginOtpAsync(dto); // {Message, Token?}


            if (!string.IsNullOrWhiteSpace(result.Token))
                return Ok(new ApiResponse(true, result.Message, result.Token));

            var ok = result.Message.StartsWith("OTP verified", System.StringComparison.OrdinalIgnoreCase);
            var payload = new ApiResponse(ok, result.Message);
            return ok ? Ok(payload) : BadRequest(payload);
        }




        ///Resends a new MFA code to the users email
        [HttpPost("resend-otp")]
        public async Task<IActionResult> ResendOtp([FromBody] ResendOtpDto dto)
        {
            var result = await _authService.ResendOtpAysnc(dto.Email);

            var ok = !(result.StartsWith("Invalid", System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("MFA is not enabled", System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("Error", System.StringComparison.OrdinalIgnoreCase));

            var payload = new ApiResponse(ok, result);
            return ok ? Ok(payload) : BadRequest(payload);
        }


        //---------------Utility--------------
        //HasOtp verified

        [HttpGet("has-verified-otp")]
        public async Task<IActionResult> HasVerifiedOtp([FromQuery] string email)
        {
            bool isVerified;
            try { isVerified = await _authService.HasVerifiedOtpAsync(email); }
            catch { isVerified = false; }  // never 500; normalize unknown user to false

            // normalize to camelCase for consistency with the rest of the API
            return Ok(new { isVerified });
        }





        //--------Password Reset-------
        //Password Reset 



        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDTO dto)
        {
            var result = await _authService.RequestPasswordResetAsync(dto);

            var ok = !(result.StartsWith("Invalid", System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("User not found", System.StringComparison.OrdinalIgnoreCase) ||
                       result.StartsWith("Error", System.StringComparison.OrdinalIgnoreCase));

            var payload = new ApiResponse(ok, result);
            return ok ? Ok(payload) : BadRequest(payload);
        }

        //Confirm Password Reset
        [HttpPost("confirm-password-reset")]
        public async Task<IActionResult> ConfirmPasswordReset([FromBody] PasswordResetConfirmDTO dto)
        {
            var result = await _authService.ConfirmPasswordResetAsync(dto);
            var ok = result.StartsWith("Password has been successfully reset",
                                       System.StringComparison.OrdinalIgnoreCase);

            var payload = new ApiResponse(ok, result);
            return ok ? Ok(payload) : BadRequest(payload);
        }

    }
}
