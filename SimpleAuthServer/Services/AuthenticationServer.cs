using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace SimpleAuthServer.Services
{
	public class AuthenticationServer : IAuthenticationServer
	{
		private readonly AppSettings _appSettings;

		private readonly List<User> _users = new List<User>
		{
			new User{ LanId = "mbelguar", FirstName = "Marcello", LastName = "Belguardi" , Password= "12345678" , Roles = new List<string> {"DesktopAdmin1", "DesktopAdmin2" } },
			new User{ LanId = "pmcartne" , FirstName = "Paul", LastName = "McCartney" , Password= "87654321" , Roles = new List<string> { "DesktopAdmin2" } },
			new User{ LanId = "jlennon" , FirstName = "John", LastName = "Lennon" , Password= "54321876" , Roles = new List<string> { "DesktopAdmin3" }}

		};

		public AuthenticationServer(IOptions<AppSettings> appSettings)
		{
			_appSettings = appSettings.Value;
		}

		public string GetToken(string lanId, string password)
		{
			var claims = new List<Claim>();

			var user = _users.Where(u => u.LanId == lanId && u.Password == password).FirstOrDefault();

			if (user == null)
				throw new KeyNotFoundException();
			
			claims.Add(new Claim(ClaimTypes.Name, user.FirstName));
			claims.Add(new Claim(ClaimTypes.Surname, user.LastName));
			claims.Add(new Claim(ClaimTypes.WindowsAccountName, user.LanId));

			foreach (var role in user.Roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role));
			}


			var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_appSettings.Secret));
			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			var token = new JwtSecurityToken(
				issuer: "simpleauthserver.aig.com",
				audience: "simpleauthclient.aig.com",
				claims: claims,
				expires: DateTime.Now.AddMinutes(30),
				signingCredentials: credentials);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}
	}
}
