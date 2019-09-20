using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using CS321_W5D1_ExerciseLogAPI.Core.Models;
using Microsoft.AspNetCore.Authorization;
using CS321_W5D1_ExerciseLogAPI.ApiModels;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Collections.Generic;
using System.Linq;
using System;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CS321_W5D1_ExerciseLogAPI.Controllers
{   
    [Authorize]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _config;
        public AuthController(UserManager<User> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _config = configuration;
        }

        //Post api/auth/register
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]RegistrationModel registration)
        {
            var newUser = new User
            {
                UserName = registration.Email,
                Email = registration.Email,
                FirstName = registration.FirstName,
                LastName = registration.LastName
            };

            var result = await _userManager.CreateAsync(newUser, registration.Password);
            if(result.Succeeded)
            {
                return Ok(newUser.ToApiModel());
            }
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return BadRequest(ModelState);

        }

        // Post api/auth/Login
        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody]LoginModel login)
        {
            IActionResult responce = Unauthorized();
            var user = await AuthenticateUserAsync(login.Email, login.Password);

            if(user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                responce = Ok(new { token = tokenString });
            }
            return responce;

        }

        private string GenerateJSONWebToken(User user)
        {
            var TokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature);
            var roles = _userManager.GetRolesAsync(user).Result;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email)
            };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: credentials
                );
            return TokenHandler.WriteToken(token);

        }
        private async Task<User> AuthenticateUserAsync(string userName, String Password)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if(user!= null && await _userManager.CheckPasswordAsync(user, Password))
            {
                return user;
            }
            return null;
        }

        // TODO: Prep Part 1: add constructor and inject UserManager 

        // TODO: Prep Part 2: inject IConfiguration in the constructor

        // TODO: Prep Part 1: Add a Registration Action (Part 1 of Prep exercise)

        // TODO: Prep Part 2: Add a login action (Part 2 of Prep exercise)

    }
}
