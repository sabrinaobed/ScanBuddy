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

        /// <summary>
        /// Registers a new user.
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDTO dto)
        {
            var result = await _authService.RegisterAsync(dto);
            return Ok(new { message = result });
        }

        /// <summary>
        /// Initiates login and sends MFA code if credentials are valid.
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO dto)
        {
            var result = await _authService.LoginAsync(dto);
            return Ok(new { message = result });
        }

        /// <summary>
        /// Verifies the MFA code and returns a JWT token if successful.
        /// </summary>
        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] UserOtpDTO dto)
        {
            var result = await _authService.VerifyOtpAsync(dto);
            return Ok(new { token = result });
        }
    }
}
