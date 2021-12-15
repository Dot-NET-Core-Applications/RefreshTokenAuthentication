using System;


namespace RefreshTokenAuthentication.Models
{
    public class AuthenticationResponse
    {
        /// <summary>
        /// Jwt token string.
        /// </summary>
        public string JwtToken { get; set; }

        /// <summary>
        /// Refresh token string.
        /// </summary>
        public string RefreshToken { get; set; }
    }
}
