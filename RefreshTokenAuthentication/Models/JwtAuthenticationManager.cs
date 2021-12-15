using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;


namespace RefreshTokenAuthentication.Models
{
    /// <summary>
    /// Class representing Authentication Manager.
    /// </summary>
    public class JwtAuthenticationManager : IJwtAuthenticationManager
    {
        /// <summary>
        /// List of user credentials mapping user name to password.
        /// </summary>
        private readonly IDictionary<string, string> users;

        /// <summary>
        /// Dictionary of users refresh token mapped to user names.
        /// </summary>
        private IDictionary<string, string> usersRefreshTokens;

        /// <summary>
        /// Unique key.
        /// </summary>
        private readonly string tokenKey;

        /// <summary>
        /// Refresh token generator.
        /// </summary>
        private readonly IRefreshTokenGenerator refreshTokenGenerator;

        /// <summary>
        /// Dictionary of mappings between usernames and refresh tokens.
        /// </summary>
        public IDictionary<string, string> UsersRefreshTokens
        {
            get
            {
                return usersRefreshTokens;
            }
            set
            {
                usersRefreshTokens = value;
            }
        }

        /// <summary>
        /// Instance of JwtAuthentication Manager.
        /// </summary>
        /// <param name="users">Dictionary of users mapping user names to passwords.</param>
        /// <param name="tokenKey">Secret token key string.</param>
        /// <param name="refreshTokenGenerator"><see cref="IRefreshTokenGenerator"/></param>
        public JwtAuthenticationManager(
            IDictionary<string, string> users,
            IDictionary<string, string> usersRefreshTokens,
            string tokenKey,
            IRefreshTokenGenerator refreshTokenGenerator)
        {
            this.users = users;
            this.usersRefreshTokens = usersRefreshTokens;
            this.tokenKey = tokenKey;
            this.refreshTokenGenerator = refreshTokenGenerator;
        }

        /// <summary>
        /// Authenticate Refresh token and Jwt Token claims identity of the user.
        /// </summary>
        /// <param name="userName">Username.</param>
        /// <param name="claims"><see cref="Claim"/></param>
        /// <returns><see cref="AuthenticationResponse"/></returns>
        public AuthenticationResponse Authenticate(string userName, Claim[] claims)
        {
            byte[] key = Encoding.ASCII.GetBytes(tokenKey);
            JwtSecurityTokenHandler jwtTokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddDays(1),
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature
                    )
                );
            string token = jwtTokenHandler.WriteToken(jwtSecurityToken);
            string refreshToken = refreshTokenGenerator.GenerateToken();

            if (UsersRefreshTokens.ContainsKey(userName))
            {
                UsersRefreshTokens[userName] = refreshToken;
            }
            else
            {
                UsersRefreshTokens.Add(userName, refreshToken);
            }

            AuthenticationResponse authenticationResponse = new AuthenticationResponse
            {
                JwtToken = token,
                RefreshToken = refreshToken
            };
            return authenticationResponse;
        }

        public AuthenticationResponse Authenticate(string username, string password)
        {
            if (users.Any(user => user.Key.Equals(username) && user.Value.Equals(password)))
            {
                byte[] key = Encoding.ASCII.GetBytes(tokenKey);
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor()
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, username),
                    }),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature
                    ),
                };
                SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
                AuthenticationResponse authenticationResponse = new AuthenticationResponse
                {
                    JwtToken = tokenHandler.WriteToken(token),
                    RefreshToken = refreshTokenGenerator.GenerateToken()
                };
                if (UsersRefreshTokens.ContainsKey(username))
                    UsersRefreshTokens[username] = authenticationResponse.RefreshToken;
                else
                    UsersRefreshTokens.Add(username, authenticationResponse.RefreshToken);

                return authenticationResponse;
            }
            else
                return default;
        }
    }
}
