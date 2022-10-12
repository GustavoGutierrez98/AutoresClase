using AutoresClase.DTOS;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Text;

namespace AutoresClase.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        public CuentasController(UserManager<IdentityUser> userManager,
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _configuration = configuration;
            _signInManager = signInManager;
        }

        //EndPoint para registrar usuarios
        [HttpPost("registrar")]
        public async Task<ActionResult<RespuestaAutenticacion>> Regsitrar(CredencialesUsuario credencialesUsuario)
        {
            var usuario = new IdentityUser { UserName = credencialesUsuario.Email, Email = credencialesUsuario.Email };
            var resultado = await _userManager.CreateAsync(usuario, credencialesUsuario.Password);

            if (resultado.Succeeded)
            {
                return await ConstruirToken(credencialesUsuario);
            }
            else
            {
                return BadRequest(resultado.Errors);
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<RespuestaAutenticacion>> Login(CredencialesUsuario credencialesUsuario)
        {
            var resultado = await _signInManager.PasswordSignInAsync(credencialesUsuario.Email,
                credencialesUsuario.Password, isPersistent: false, lockoutOnFailure: false);

            if (resultado.Succeeded)
            {
                return await ConstruirToken(credencialesUsuario);
            }
            else
            {
                return BadRequest("Login Incorrecto");
            }
        }

        [HttpGet("renovarToken")]
        public async Task<ActionResult<RespuestaAutenticacion>> Renovar()
        {
            var emailClaim = HttpContext.User.Claims.Where(x => x.Type == "email").FirstOrDefault();
            var credencialesUsuario = new CredencialesUsuario()
            {
                Email = emailClaim.Value
            };
            return await ConstruirToken(credencialesUsuario);
        }

        [HttpGet("HacerAdmin")]
        public async Task<ActionResult> HacerAdmin(AgregarRol agregarRol) 
        {
            var usuario = await _userManager.FindByEmailAsync(agregarRol.Email);
            if (usuario != null) 
            {
                await _userManager.AddClaimAsync(usuario, new Claim("esAdmin", "1"));
            }
            return BadRequest();
        }

        [HttpPost("RemoverAdmin")]
        public async Task<ActionResult> RemoverAdmin(AgregarRol agregarRol)
        {
            var usuario = await _userManager.FindByEmailAsync(agregarRol.Email);
            if (usuario != null)
            {
                await _userManager.RemoveClaimAsync(usuario, new Claim("esAdmin", "1"));
            }
            return BadRequest();
        }

        private Task<RespuestaAutenticacion> ConstruirToken(CredencialesUsuario credencialesUsuario)
        {
            var claims = new List<Claim>()
            {
                new Claim("email", credencialesUsuario.Email),
            };

            //Agregar claim
            //claims.AddRange()

            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["LlaveJWT"]));
            var creds = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

            var expiracion = DateTime.UtcNow.AddDays(1);

            var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims,
                expires: expiracion, signingCredentials: creds);

            return Task.FromResult(new RespuestaAutenticacion
            {
                Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
                Expiracion = expiracion,
            });
        }
    }
}
