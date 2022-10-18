using System.ComponentModel.DataAnnotations;
namespace AuthWithJwt.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        
        [Display(Name="Email Address")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public DateTime Joined { get; set; } = DateTime.Now;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}