using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RefreshTokenAuthentication.Models;

namespace RefreshTokenAuthentication.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class NameController : ControllerBase
    {
        /// <summary>
        /// Jwt authentication manager.
        /// </summary>
        private readonly IJwtAuthenticationManager jwtAuthenticationManager;

        /// <summary>
        /// Jwt token refresher.
        /// </summary>
        private readonly ITokenRefresher tokenRefresher;

        public NameController(IJwtAuthenticationManager jwtAuthenticationManager, ITokenRefresher tokenRefresher)
        {
            this.jwtAuthenticationManager = jwtAuthenticationManager;
            this.tokenRefresher = tokenRefresher;
        }

        // GET: api/Name
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "New York", "New Jersey" };
        }

        // GET: api/Name/5
        [HttpGet("{id}", Name = "Get")]
        public string Get(int id)
        {
            return "New Jersey";
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] UserCredential credential)
        {
            AuthenticationResponse token = jwtAuthenticationManager.Authenticate(credential.UserName, credential.Password);
            return token is null ? Unauthorized() : Ok(token);
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshCred refresh)
        {
            AuthenticationResponse token = tokenRefresher.Refresh(refresh);
            return token is null ? Unauthorized() : Ok(token);
        }
    }
}
