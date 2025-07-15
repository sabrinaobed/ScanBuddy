using System.Net;
using System.Net.Mail;
using ClassLibrary.ScanBuddy.Backend.Interfaces;
using ScanBuddy.JWTConfiguration;

namespace ScanBuddy.Services
{
    public class EmailService :IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                var smtpClient = new SmtpClient
                {
                    Host = _configuration["Smtp:Host"],
                    Port = int.Parse(_configuration["Smtp:Port"]),
                    EnableSsl = true,
                    Credentials = new NetworkCredential(
                        _configuration["Smtp:Username"],
                        _configuration["Smtp:Password"])
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_configuration["Smtp:From"]),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true  // Enables HTML email formatting
                };

                mailMessage.To.Add(toEmail);

                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                // You can log the error here using any logging framework
                throw new Exception($"Failed to send email: {ex.Message}", ex);
            }
        }
    }
}

