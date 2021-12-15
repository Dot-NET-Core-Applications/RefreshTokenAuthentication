namespace RefreshTokenAuthentication.Models
{
    public interface ITokenRefresher
    {
        AuthenticationResponse Refresh(RefreshCred refresh);
    }
}