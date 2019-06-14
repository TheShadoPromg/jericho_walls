using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
    public class ServiceController : ControllerBase
    {
        private readonly IAuthenticationRepository _authenticationRepository;
        private readonly IServiceRepository _repository;
        private readonly IConfiguration _config;
        private readonly ILogger<ServiceController> _logger;

        public ServiceController(IAuthenticationRepository authenticationRepository, 
                                IServiceRepository repository,
                                IConfiguration config,
                                ILogger<ServiceController> logger)
        {
            this._authenticationRepository = authenticationRepository;
            this._repository = repository;
            this._config = config;
            this._logger = logger;
        }

        // GET: api/Service
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var authorization = await AuthenticationHelper.Authorize(
                Request.Headers["Authorization"],
                _authenticationRepository,
                _logger,
                _config.GetValue<string>("JWTIssuer"),
                "read-all-service"
            );

            if (authorization == null)
            {
                return Unauthorized();
            }

            if (authorization.Forbiden)
            {
                return Forbid();
            }

            var services = await _repository.GetAll();

            return Ok(services);
        }

        // GET: api/Service
        [HttpGet("[action]/{service}")]
        public async Task<IActionResult> NewKey(string service)
        {
            //var authorization = await AuthenticationHelper.Authorize(
            //    Request.Headers["Authorization"],
            //    _authenticationRepository,
            //    _logger,
            //    _config.GetValue<string>("JWTIssuer"),
            //    "read-all-service"
            //);

            //if (authorization == null)
            //{
            //    return Unauthorized();
            //}

            //if (authorization.Forbiden)
            //{
            //    return Forbid();
            //}
            var serv = await _repository.GetByName(service);

            if (serv == null)
            {
                return new BadRequestObjectResult(new { Message = $"El servicio {service} no se encontró en el sistema." });
            }

            var rsa = RSA.Create();
            rsa.ImportParameters(AuthenticationHelper.DeserializeRSAKey(serv.PrivateKey));
            rsa.ImportParameters(AuthenticationHelper.DeserializeRSAKey(serv.PublicKey));

            var key = rsa.SignData(Encoding.ASCII.GetBytes("Secret Key"), HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

            return Ok(new { Message = key });
        }

        // POST: api/Service
        [HttpPost]
        public async Task<IActionResult> Post([FromBody] ServiceModel model)
        {
            //Authorize
            var authorization = await AuthenticationHelper.Authorize(
                  Request.Headers["Authorization"],
                  _authenticationRepository,
                  _logger,
                  _config.GetValue<string>("JWTIssuer"),
                  "create-service"
              );

            if (authorization == null)
            {
                return Unauthorized();
            }

            if (authorization.Forbiden)
            {
                return Forbid();
            }

            //Validate user data
            var validator = await new ServiceModelValidator().ValidateAsync(model);

            if (!validator.IsValid)
            {
                var errors = validator.Errors.Select(e => new
                {
                    e.PropertyName,
                    Message = e.ErrorMessage
                });

                _logger.LogInformation($"Failed to validate service. {errors}");
                return new BadRequestObjectResult(errors);
            }

            //Fulfill request
            try
            {
                var service = await _repository.Create(model, authorization.User.Identifier);
                return Created("", service);
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
                    _logger.LogError("Failed to create service by SqlException Message {@Message} StackTrace {@StackTrace}", sqlE.Message, sqlE.StackTrace);
                    return StatusCode(500);
                }
            }
            catch (Exception e2)
            {
                _logger.LogError("Message {@Message} StackTrace {@StackTrace}", e2.Message, e2.StackTrace);
                return StatusCode(500);
            }
        }

        // PUT: api/Service
        [HttpPut]
        public async Task<IActionResult> Put([FromBody] ServiceModel model)
        {
            //Authorize
            var authorization = await AuthenticationHelper.Authorize(
               Request.Headers["Authorization"],
               _authenticationRepository,
               _logger,
               _config.GetValue<string>("JWTIssuer"),
               "update-service"
           );

            if (authorization == null)
            {
                return Unauthorized();
            }

            if (authorization.Forbiden)
            {
                return Forbid();
            }

            //Validate user data
            var validator = await new ServiceModelValidator().ValidateAsync(model);

            if (!validator.IsValid)
            {
                var errors = validator.Errors.Select(e => new
                {
                    e.PropertyName,
                    Message = e.ErrorMessage
                });

                _logger.LogInformation($"Failed to validate service. {errors}");
                return new BadRequestObjectResult(errors);
            }
           
            //Fulfill request
            try
            {
                await _repository.Update(model, authorization.User.Identifier);
                return NoContent();
            }
            catch (MySqlException sqlE)
            {
                _logger.LogError("Failed to update service by SqlException Message {@Message} StackTrace {@StackTrace}", sqlE.Message, sqlE.StackTrace);
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
