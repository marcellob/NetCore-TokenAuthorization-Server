namespace SimpleAuthServer.Services
{
	public interface IAuthenticationServer
	{
		string GetToken(string lanId, string password);
	}
}