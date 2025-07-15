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

        /// Registers a new user.
      
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDTO dto)
        {
            var result = await _authService.RegisterAsync(dto);
            return Ok(new { message = result });
        }

  
        /// Initiates login and sends MFA code if credentials are valid.
      
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO dto)
        {
            var result = await _authService.LoginAsync(dto);
            return Ok(new { message = result });
        }

        
        /// Verifies the MFA code and returns a JWT token if successful.
       
        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] UserOtpDTO dto)
        {
            var result = await _authService.VerifyOtpAsync(dto);
            return Ok(new { token = result });
        }

        ///Resends a new MFA code to the users email
        [HttpPost("resend-otp")]
        public async Task<IActionResult> ResendOtp([FromBody] string email)
        {
            var result = await _authService.ResendOtpAysnc(email);
            return Ok(new { message = result });
        }

        //HasOtp verified
        [HttpGet("has-verified-otp")]
        public async Task<IActionResult> HasVerifiedOtp([FromQuery] string email)
        {
            var isVerified = await _authService.HasVerifiedOtpAsync(email);
            return Ok(new { IsVerified = isVerified });
        }


    }
}
