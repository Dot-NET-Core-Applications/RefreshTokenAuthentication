using System;
using System.Security.Cryptography;


namespace RefreshTokenAuthentication.Models
{
    public class RefreshTokenGenerator : IRefreshTokenGenerator
    {
        public RefreshTokenGenerator()
        {
        }

        public string GenerateToken()
        {
            byte[] randomNumber = new byte[32];
            using (RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create())
            {
                randomNumberGenerator.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}
