using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("signin")]
    public IActionResult SignIn([FromBody] LoginRequest request)
    {
        // Verifica se os parâmetros foram fornecidos
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { Message = "Username or password cannot be empty" });
        }

        // Autentica no AD usando LDAP
        using PrincipalContext context = new PrincipalContext(ContextType.Machine);
        bool isValid = context.ValidateCredentials(request.Username, request.Password);

        if (isValid)
        {
            var token = GenerateJwtToken(request.Username);
            return Ok(new { Message = "User authenticated successfully", Token = token });
        }
        else
        {
            return Unauthorized(new { Message = "Invalid username or password" });
        }
    }

    [HttpGet("info")]
    [Authorize] // Garante que o usuário precisa estar autenticado para acessar este endpoint
    public IActionResult Info()
    {
        // Verifica se o usuário está autenticado
        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            // Retorna informações do usuário autenticado
            var userName = User.Identity.Name; // Nome do usuário logado
            var userClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList(); // Claims do usuário

            return Ok(new
            {
                Message = "User authenticated successfully",
                UserName = userName,
                Claims = userClaims
            });
        }

        // Caso o usuário não esteja autenticado, retorna Unauthorized
        return Unauthorized(new { Message = "User is not authenticated" });
    }

    [HttpGet("test-jwt")]
    [Authorize] 
    public IActionResult TestJwt()
    {
        // Verifica se o token JWT foi passado e se o usuário está autenticado
        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            var userName = User.Identity.Name; // Obtém o nome do usuário do token
            var userClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList(); // Obtém todas as claims do token

            return Ok(new
            {
                Message = "JWT is valid",
                UserName = userName,
                Claims = userClaims
            });
        }

        // Retorna Unauthorized se o token for inválido ou ausente
        return Unauthorized(new { Message = "Invalid or missing JWT token" });
    }

    private string GenerateJwtToken(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

        // Claims adicionais podem ser adicionadas aqui
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username), // Nome do usuário
            new Claim(JwtRegisteredClaimNames.Sub, username), // Sub claim
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // ID do token
            new Claim(JwtRegisteredClaimNames.Exp, DateTime.UtcNow.AddMinutes(10).ToString()), // Tempo de expiração
            new Claim(ClaimTypes.Role, "User"), // Exemplo de Role (pode adicionar diferentes roles)
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}

// Classe para representar a requisição de login
public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
