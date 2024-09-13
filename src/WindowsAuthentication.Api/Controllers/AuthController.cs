using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IConfiguration configuration, ILogger<AuthController> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    [HttpPost("signin")]
    public IActionResult SignIn([FromBody] LoginRequest request)
    {
        // Verifica se os parâmetros foram fornecidos
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            _logger.LogWarning("Tentativa de login falhou: Nome de usuário ou senha ausentes.");
            return BadRequest(new { Message = "Username or password cannot be empty" });
        }

        // Autentica no AD usando LDAP
        _logger.LogInformation("Iniciando autenticação para o usuário: {Username}", request.Username);
        using PrincipalContext context = new PrincipalContext(ContextType.Machine);
        bool isValid = context.ValidateCredentials(request.Username, request.Password);

        if (isValid)
        {
            _logger.LogInformation("Usuário {Username} autenticado com sucesso.", request.Username);

            // Recupera informações adicionais do usuário
            using UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, request.Username);

            if (userPrincipal != null)
            {
                var userInfo = new
                {
                    Username = userPrincipal.SamAccountName, // Nome de usuário
                    FullName = userPrincipal.DisplayName, // Nome completo
                    Email = userPrincipal.EmailAddress, // Email do usuário
                    Groups = userPrincipal.GetAuthorizationGroups().Select(g => g.Name).ToList() // Grupos do AD
                };

                var token = GenerateJwtToken(userPrincipal.SamAccountName);

                return Ok(new
                {
                    Message = "User authenticated successfully",
                    Token = token,
                    UserDetails = userInfo // Retorna as informações adicionais do usuário
                });
            }
            else
            {
                _logger.LogError("Falha ao recuperar as informações do usuário {Username}.", request.Username);
            }
        }
        else
        {
            _logger.LogWarning("Tentativa de login inválida para o usuário {Username}.", request.Username);
        }
        return Unauthorized(new { Message = "Invalid username or password" });
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

            _logger.LogInformation("Token JWT validado com sucesso para o usuário: {UserName}", userName);

            return Ok(new
            {
                Message = "JWT is valid",
                UserName = userName,
                Claims = userClaims
            });
        }

        _logger.LogWarning("Token JWT inválido ou ausente na tentativa de acesso.");
        return Unauthorized(new { Message = "Invalid or missing JWT token" });
    }

    private string GenerateJwtToken(string username)
    {
        _logger.LogInformation("Gerando token JWT para o usuário: {Username}", username);

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

        // Claims adicionais podem ser adicionadas aqui
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username), // Nome do usuário
            new Claim(JwtRegisteredClaimNames.Sub, username), // Sub claim
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // ID do token
            new Claim(JwtRegisteredClaimNames.Exp, DateTime.UtcNow.AddMinutes(10).ToString()), // Tempo de expiração
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);

        _logger.LogInformation("Token JWT gerado com sucesso para o usuário: {Username}", username);
        return jwtToken;
    }
}

// Classe para representar a requisição de login
public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
