using System;


namespace RefreshTokenAuthentication.Models
{
    public interface IRefreshTokenGenerator
    {
        /// <summary>
        /// Generate refresh token string.
        /// </summary>
        /// <returns>Refresh token string.</returns>
        string GenerateToken();
    }
}
