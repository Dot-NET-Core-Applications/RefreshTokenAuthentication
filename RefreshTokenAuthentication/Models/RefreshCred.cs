using System;


namespace RefreshTokenAuthentication.Models
{
    public class RefreshCred
    {
        /// <summary>
        /// JwtToken string.
        /// </summary>
        public string JwtToken { get; set; }

        /// <summary>
        /// Refresh token string.
        /// </summary>
        public string RefreshToken { get; set; }
    }
}
