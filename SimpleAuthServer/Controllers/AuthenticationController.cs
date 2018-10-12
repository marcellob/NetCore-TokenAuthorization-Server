using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SimpleAuthServer.Services;
using System.Collections.Generic;

namespace SimpleAuthServer.Controllers
{
	[Route("api/Authentication")]
	[ApiController]
	[Authorize]
	public class AuthenticationController : ControllerBase
	{

		private IAuthenticationServer _authenticationService;

		public AuthenticationController(IAuthenticationServer authenticationService)
		{
			_authenticationService = authenticationService;
		}

		/// <summary>
		/// This endpoint consent all users that provide user/password to ask for a JWT token; 
		/// the users are stored here in the auth server and the token is provided ony if the user is known
		/// The access to this endpoint is anonymous
		/// </summary>
		/// <param name="userParam"></param>
		/// <returns></returns>
		[AllowAnonymous]
		[HttpPost("Authenticate")]
		public IActionResult Authenticate([FromBody] UserParam userParam)
		{
			var token = string.Empty;
			try
			{
				 token = _authenticationService.GetToken(userParam.LanId, userParam.Password);
					return Ok(token);
			}
			catch(KeyNotFoundException)
			{
				return BadRequest(new { message = "Username or password is incorrect" });
			}
		
		}
	
		/// <summary>
		/// This authentication server support Single Sign On (Windows Authentication) provided IIS is configured under the same users domain
		/// In this endpoint only the users that belong to a specific Active Directory group can access 
		/// (currently it only returns the user identity, but can be extended to return the token exactly as the endpoint above)
		/// </summary>
		/// <returns></returns>
		[Authorize (Roles = "AIU_Ireland-UK_All_Users")]
		[HttpGet]
		public dynamic Get()
		{
			var user = HttpContext.User;
			return user.Identity.Name;
		}
	}
}
