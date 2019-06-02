using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using rde.edu.do_jericho_walls.Helpers;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;

namespace rde.edu.do_jericho_walls.Controllers
{
    [Route("api/jericho_walls/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationRepository _repository;
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _config;
        private readonly ILogger _logger;

        public AuthenticationController(IAuthenticationRepository repository,
                                        IUserRepository userRepository,
                                        IConfiguration config,
                                        ILogger<AuthenticationController> logger)
        {
            this._repository = repository;
            this._userRepository = userRepository;
            this._config = config;
            this._logger = logger;
        }

        // POST: api/Authentication
        [HttpPost]
        public async Task<IActionResult> Post([FromBody] AuthenticationModel model)
        {
            var validator = await new AuthenticationModelValidator().ValidateAsync(model);

            if (!validator.IsValid)
            {
                var errors = validator.Errors.Select(e => new
                {
                    e.PropertyName,
                    Message = e.ErrorMessage
                });

                _logger.LogInformation($"Failed to validate user. {errors}");
                return new BadRequestObjectResult(errors);
            }

            try
            {
                //Authenticates the given email with the given password
                var authentication = await _repository.ValidatePassword(model);

                if (authentication == null)
                {
                    return Unauthorized(new { Message = "El correo electrónico y/o contraseña son incorrectos." });
                }

                
                //Get user complete information
                var user = await _userRepository.GetById(authentication.Id);

                if (user == null)
                {
                    _logger.LogError(@"
                        For some strange reason the user is null. This is when calling userRepository.GetById. This
                        was call with an id of {@Id}", authentication.Id);
                    return StatusCode(500);
                }

                //Create JWT
                var token = AuthenticationHelper.CreateJWT(
                    user, 
                    authentication.PrivateKey, 
                    _config.GetValue<string>("JWTIssuer")
                );

                return Ok(new { Message = token });
            }
            catch (Exception e2)
            {
                _logger.LogError("Message {@Message} StackTrace {@StackTrace}", e2.Message, e2.StackTrace);
                return StatusCode(500);
            }
        }
    }
}
