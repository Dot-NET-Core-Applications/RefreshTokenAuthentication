using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;


namespace RefreshTokenAuthentication.Models
{
    public class TokenRefresher : ITokenRefresher
    {
        /// <summary>
        /// Private key.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// JwtAuthentication manager.
        /// </summary>
        private readonly IJwtAuthenticationManager jwtAuthenticationManager;

        /// <summary>
        /// Instantiate TokenRefresher
        /// </summary>
        /// <param name="key">Private key.</param>
        public TokenRefresher(byte[] key, IJwtAuthenticationManager jwtAuthenticationManager)
        {
            this.key = key;
            this.jwtAuthenticationManager = jwtAuthenticationManager;
        }
        public AuthenticationResponse Refresh(RefreshCred refresh)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(refresh.JwtToken,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                }, out validatedToken);
            JwtSecurityToken token = validatedToken as JwtSecurityToken;
            if (token != null && token.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
            {
                string userName = principal.Identity.Name;
                string refreshToken = jwtAuthenticationManager.UsersRefreshTokens[userName];
                if (refresh.RefreshToken == refreshToken)
                {
                    return jwtAuthenticationManager.Authenticate(userName, principal.Claims.ToArray());
                }
                else
                    throw new SecurityTokenException("Invalid token passed!");
            }
            else
                throw new SecurityTokenException("Invalid token passed!");
        }
    }
}
