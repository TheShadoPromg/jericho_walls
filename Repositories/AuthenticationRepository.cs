using Microsoft.Extensions.Configuration;
using MySql.Data.MySqlClient;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using rde.edu.do_jericho_walls.Helpers;

namespace rde.edu.do_jericho_walls.Repositories
{
    public class AuthenticationRepository : IAuthenticationRepository
    {
        private readonly IConfiguration config;

        public AuthenticationRepository(IConfiguration config)
        {
            this.config = config;
        }

        /// <summary>
        /// Get a connection to the database
        /// </summary>
        private IDbConnection Connection
        {
            get
            {
                var conn = new MySqlConnection(config.GetConnectionString("DefaultConnection"));
                conn.Open();
                return conn;
            }
        }

        /// <summary>
        /// Gets the public and private key from the database also gets the state
        /// of the user to check if the user is active and can access the system.
        /// The user search is by the Id, Identifier and Email.
        /// </summary>
        /// 
        /// <param name="model"></param>
        /// <returns>Returns null if user is not found, or account is inactive.</returns>
        public async Task<AuthenticationSecrets> GetRSAKeys(UserModel model)
        {
            var secrets = await Connection.QueryFirstOrDefaultAsync<AuthenticationSecrets>(
                "ReadUserKeys",
                new
                {
                    p_id = model.Id,
                    p_identifier = model.Identifier,
                    p_email = model.Email
                },
                commandType: CommandType.StoredProcedure
            );

            return secrets == null ? null : secrets.Active ? secrets : null;
        }

        /// <summary>
        /// Validates the given <see cref="AuthenticationModel"> the password are equal
        /// if the given password can generate the same password hash that it's stored in
        /// the database. The generate password need to be with the hash that is also stored
        /// in the database. If the account is not active it will automatically return null.
        /// </summary>
        /// 
        /// <param name="model"></param>
        /// <returns>Returns null if user is not found, password doesn't match or account is inactive.</returns>
        public async Task<AuthenticationSecrets> ValidatePassword(AuthenticationModel model)
        {
            var secrets = await Connection.QueryFirstOrDefaultAsync<AuthenticationSecrets>(
                "ReadUserPassword",
                new { p_email = model.Email },
                commandType: CommandType.StoredProcedure
            );

            if (secrets == null || (secrets != null && (secrets.Password == null || !secrets.Active)))
            {
                return null;
            }

            string[] saltAndHash = secrets.Password.Split("|");
            string hash = AuthenticationHelper.HashPasswordWithSalt(model.Password, saltAndHash[0]);

            return hash == saltAndHash[1] ? secrets : null;
        }
    }
}
