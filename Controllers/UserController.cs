using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MySql.Data.MySqlClient;
using rde.edu.do_jericho_walls.Helpers;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;

namespace rde.edu.do_jericho_walls.Controllers
{
    [Route("api/jericho_walls/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthenticationRepository _authenticationRepository;
        private readonly IUserRepository _repository;
        private readonly IConfiguration _config;
        private readonly ILogger<UserController> _logger;

        public UserController(IAuthenticationRepository authenticationRepository,
                              IUserRepository repository,
                              IConfiguration config,
                              ILogger<UserController> logger)
        {
            this._authenticationRepository = authenticationRepository;
            this._repository = repository;
            this._config = config;
            this._logger = logger;
        }

        // GET: api/User
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var authorization = await AuthenticationHelper.Authorize(
                Request.Headers["Authorization"],
                _authenticationRepository,
                _logger,
                _config.GetValue<string>("JWTIssuer"),
                "read-all-users"
            );

            if (authorization == null)
            {
                return Unauthorized();
            }

            if (authorization.Forbiden)
            {
                return Forbid();
            }

            var users = await _repository.GetAll();

            return Ok(users);
        }

        // POST: api/User
        [HttpPost]
        public async Task<IActionResult> Post([FromBody] UserModel model)
        {
            var validator = await new UserModelValidator().ValidateAsync(model);

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
                var created = await _repository.Create(model);
                return Created("", created);
            }
            catch (MySqlException sqlE)
            {
                if (sqlE.Number == 409)
                {
                    return new BadRequestObjectResult(new
                    {
                        sqlE.Message,
                    });
                }
                else
                {
                    _logger.LogError("Failed to insert user by SqlException Message {@Message} StackTrace {@StackTrace}", sqlE.Message, sqlE.StackTrace);
                    return StatusCode(500);
                }
            }
            catch (Exception e2)
            {
                _logger.LogError("Message {@Message} StackTrace {@StackTrace}", e2.Message, e2.StackTrace);
                return StatusCode(500);
            }
        }

        // PUT: api/User
        [HttpPut]
        public async Task<IActionResult> Put([FromBody] UserModel model)
        {
            var authorization = await AuthenticationHelper.Authorize(
                Request.Headers["Authorization"],
                _authenticationRepository,
                _logger,
                _config.GetValue<string>("JWTIssuer"),
                "update-user"
            );

            if (authorization == null)
            {
                return Unauthorized();
            }

            if(authorization.Forbiden)
            {
                return Forbid();
            }

            var validator = await new UserModelValidator(update: true).ValidateAsync(model);

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
                await _repository.Updated(model, authorization.User.Identifier);
                return NoContent();
            }
            catch (MySqlException sqlE)
            {
                _logger.LogError("Failed to update user by SqlException Message {@Message} StackTrace {@StackTrace}", sqlE.Message, sqlE.StackTrace);
                return StatusCode(500);
            }
            catch (Exception e2)
            {
                _logger.LogError("Message {@Message} StackTrace {@StackTrace}", e2.Message, e2.StackTrace);
                return StatusCode(500);
            }
        }
    }
}
