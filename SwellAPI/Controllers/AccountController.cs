using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SwellAPI.DTO;

namespace SwellAPI.Controllers
{

        [Route("api/[controller]")]
        [ApiController]
        [ApiConventionType(typeof(DefaultApiConventions))]
        public class AccountController : ControllerBase
        {
            private readonly SignInManager<IdentityUser> _signInManager;
            private readonly UserManager<IdentityUser> _userManager;
            private readonly IConfiguration _config; //Hierin wordt de secret key in opgeslagen. 
                                                     //Het eerste dat een gebruiker doet is zich registreren. => api/account/register
            public AccountController(
              SignInManager<IdentityUser> signInManager,
              UserManager<IdentityUser> userManager,
              IConfiguration config)
            {
                _signInManager = signInManager;
                _userManager = userManager;
                _config = config;
            }

            /// <summary>
            /// Login
            /// </summary>
            /// <param name="model">the login details</param>
            [AllowAnonymous]
            [HttpPost]
            //DIT IS DE LOG IN.
            public async Task<ActionResult<String>> CreateToken(LoginDTO model) //Hierin staat de mail en password. In de model kan je weer validatie vinden. 
            {
                //Gebruiker opzoeken a.d.h.v usermanager. 
                var user = await _userManager.FindByNameAsync(model.Email);

                if (user != null)
                {
                    //Kijken off password klopt. 
                    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

                    if (result.Succeeded)
                    {
                        //Als password klopt, wordt token terug opgevraagt en terug gestuurd naar de view.
                        string token = GetToken(user);
                        return Created("", token); //returns only the token                    
                    }
                }
                //Als account niet bestaat, Bad Request (Code 400).
                return BadRequest();
            }


            /// <summary>
            /// Register a user
            /// </summary>
            /// <param name="model">the user details</param>
            /// <returns></returns>
            //Dit is de aller eerste methode is opgeroepen wordt in  deze controller. Het meegegeven password en naam etc zit in het RegisterDTO object. De DTO is hetzelfde als een 'viewmodel'.
            //Alle validatie die in deze DTO model staat, wordt ook gecontroleerd in Swagger. 
            [AllowAnonymous]
            [HttpPost("register")]
            public async Task<ActionResult<String>> Register(RegisterDTO model)
            {
                //Hier wordt de gebruiker aangemaakt. 
                IdentityUser user = new IdentityUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    //Als de gebruiker aangemaakt is in Identity, dan wordt ze toegevoegd in Entity.

                    //Een gebruiker heeft een token nodig, deze wordt aangemaakt. (method GetToken)
                    string token = GetToken(user);
                    return Created("", token);
                }
                return BadRequest();
            }

            private String GetToken(IdentityUser user)
            {
                // Create the token
                var claims = new[]
                {
                //Sub = Subject. Je kan  ook 'Rollen' toevoegen. Dan voeg je RoleClaims toe.
                //Claims zijn informatie over de gbruiker, het is om te weten wie ze is.
              new Claim(JwtRegisteredClaimNames.Sub, user.Email),
              new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName)
            };

                //Hier wordt het gehasht.
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Tokens:Key"]));

                //Hier geef je een hashing algoritme mee.
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                //Je kan parameters meegeven, (wie ze aanmaakt, de audience, ... Hier NIET nodig. (dus daarom 2 nulls)
                var token = new JwtSecurityToken(
                  null, null,
                  claims,
                  //Een token mag maar een bepaalde periode geldig zijn. Als het tokn verloopt, moet je opnieuw inloggen.
                  expires: DateTime.Now.AddMinutes(30),
                  //Dit is belangrijk.
                  signingCredentials: creds);

                //Hier geef je het token mee en wordt het aangemaakt. Het wordt gereturned in String vorm.
                return new JwtSecurityTokenHandler().WriteToken(token);
            }
        
    }
}