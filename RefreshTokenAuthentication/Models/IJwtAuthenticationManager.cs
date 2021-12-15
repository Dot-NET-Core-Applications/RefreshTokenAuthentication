using System;
using System.Security.Claims;
using System.Collections.Generic;


namespace RefreshTokenAuthentication.Models
{
    public interface IJwtAuthenticationManager
    {
        /// <summary>
        /// Authenticate user.
        /// </summary>
        /// <param name="username">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns><see cref="AuthenticationResponse"/></returns>
        AuthenticationResponse Authenticate(string username, string password);

        /// <summary>
        /// Authenticate Refresh token and Jwt Token claims identity of the user.
        /// </summary>
        /// <param name="userName">Username.</param>
        /// <param name="claims"><see cref="Claim"/></param>
        /// <returns><see cref="AuthenticationResponse"/></returns>
        AuthenticationResponse Authenticate(string userName, Claim[] claims);

        /// <summary>
        /// Dictionary of mappings between usernames and refresh tokens.
        /// </summary>
        IDictionary<string, string> UsersRefreshTokens { get; set; }

    }
}
