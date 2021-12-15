using System;


namespace RefreshTokenAuthentication.Models
{
    /// <summary>
    /// Class representing user credential.
    /// </summary>
    public class UserCredential
    {
        /// <summary>
        /// User name.
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// User password.
        /// </summary>
        public string Password { get; set; }
    }
}
