using Microsoft.Extensions.Configuration;
using MySql.Data.MySqlClient;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using System.Security.Cryptography;
using System;
using rde.edu.do_jericho_walls.Helpers;
using System.Linq;
using System.Collections.Generic;

namespace rde.edu.do_jericho_walls.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly IConfiguration config;

        public UserRepository(IConfiguration config)
        {
            this.config = config;
        }

        /// <summary>
        /// Gets a connection to the database
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
        /// Get a <see cref="UserModel"/> by the given Id.
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public async Task<UserModel> GetById(int id)
        {
            var conn = Connection;
            UserModel user = null;

            var result = await conn.QueryAsync<UserModel, Service, Permission, UserModel>(
                "ReadUserWithGrants",
                param: new { p_id = id },
                map: (u, service, p) =>
                {
                    if (user == null)
                    {
                        user = u;
                    }

                    if (service != null)
                    {
                        var s = user.ServicePermissions.Where(s => s.Name == service.Name).FirstOrDefault();

                        if (s != null)
                        {
                            if (p != null)
                            {
                                s.Permissions.Add(p);
                            }
                        }
                        else
                        {
                            if (p != null)
                            {
                                service.Permissions.Add(p);
                            }
                            user.ServicePermissions.Add(service);
                        }
                    }

                    return user;
                },
                splitOn: "name,name",
                commandType: CommandType.StoredProcedure
            );

            conn.Close();

            return result.Distinct().ToList().First();
        }

        /// <summary>
        /// Get a list of <see cref="UserModel"/> with there given grants.
        /// </summary>
        /// <returns></returns>
        public async Task<IList<UserModel>> GetAll()
        {
            using (var conn = Connection)
            {
                var users = new Dictionary<int, UserModel>();

                var result = await conn.QueryAsync<UserModel, Service, Permission, UserModel>(
                    "ReadUserWithGrantsAll",
                    map: (u, service, p) =>
                    {
                        if (!users.TryGetValue(u.Id, out UserModel user))
                        {
                            user = u;
                            users.Add(user.Id, user);
                        }

                        if (service != null)
                        {
                            var s = user.ServicePermissions.Where(s => s.Name == service.Name).FirstOrDefault();

                            if (s != null)
                            {
                                if (p != null)
                                {
                                    s.Permissions.Add(p);
                                }
                            }
                            else
                            {
                                if (p != null)
                                {
                                    service.Permissions.Add(p);
                                }
                                user.ServicePermissions.Add(service);
                            }
                        }

                        return user;
                    },
                    splitOn: "name,name",
                    commandType: CommandType.StoredProcedure
                );

                return result.Distinct().ToList();
            }
        }

        /// <summary>
        /// Create a new user. Generates a new GUID to be inserted in the database.
        /// It creates a RSA 2048, and stored the public and private key in the database
        /// in XML format. This RSA is to be use to generate the JWT. And uses <see cref="HashPassword"/>
        /// to hash the user password.
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Returns a <see cref="UserModel"/> with the id and identifier assign.</returns>
        public async Task<UserModel> Create(UserModel model)
        {
            using (var conn = Connection)
            {
                //Generate GUID for the database user registry
                var guid = Guid.NewGuid();

                //Generate RSA keys for JWTs
                var csp = RSA.Create(2048);
                var publicKey = csp.ExportParameters(false);
                var privateKey = csp.ExportParameters(true);

                //Create user registry
                var id = await conn.QueryFirstAsync<int>("CreateUser",
                    new
                    {
                        p_guid = guid.ToString(),
                        p_firstName = model.FirstName,
                        p_lastName = model.LastName,
                        p_email = model.Email,
                        p_password = AuthenticationHelper.HashPassword(model.Password),
                        p_publicKey = AuthenticationHelper.SerializeRSAKey(publicKey),
                        p_privateKey = AuthenticationHelper.SerializeRSAKey(privateKey),
                        p_active = model.Active,
                        p_tokenDuration = model.TokenDuration,
                        p_recordBy = config.GetValue<string>("SystemName"),
                    },
                    commandType: CommandType.StoredProcedure
                );

                model.Id = id;
                model.Identifier = guid;
                return model;
            }
        }

        /// <summary>
        /// Creates a Dapper transaction and updates the user personal information. It updates
        /// the services access and the services' permissions' access.
        /// </summary>
        /// 
        /// <param name="model"></param>
        /// <param name="accessBy"></param>
        /// <returns></returns>
        public async Task Updated(UserModel model, Guid accessBy)
        {
            using (var conn = Connection)
            {
                using (var transaction = conn.BeginTransaction())
                {

                    await conn.ExecuteAsync(
                        "UpdateUser",
                        new
                        {
                            p_id = model.Id,
                            p_identifier = model.Identifier,
                            p_email = model.Email,
                            p_firstName = model.FirstName,
                            p_lastName = model.LastName,
                            p_active = model.Active,
                            p_tokenDuration = model.TokenDuration
                        },
                        commandType: CommandType.StoredProcedure
                    );

                    foreach (var service in model.ServicePermissions)
                    {
                        await conn.ExecuteAsync(
                            "UpdateOrCreateServiceUserAccess",
                            new
                            {
                                p_serviceIdentifier = service.Identifier,
                                p_email = model.Email,
                                p_hasAccess = service.HasAccess,
                                p_createdByUserIdentifier = accessBy,
                                p_recordBy = config.GetValue<string>("SystemName")
                            },
                            commandType: CommandType.StoredProcedure
                        );

                        foreach (var permission in service.Permissions)
                        {
                            await conn.ExecuteAsync(
                            "UpdateOrCreateServiceUserPermissions",
                            new
                            {
                                p_serviceIdentifier = service.Identifier,
                                p_email = model.Email,
                                p_permissionName = permission.Name,
                                p_hasAccess = permission.HasAccess,
                                p_createdByUserIdentifier = accessBy,
                                p_recordBy = config.GetValue<string>("SystemName")
                            },
                            commandType: CommandType.StoredProcedure
                        );
                        }
                    }

                    transaction.Commit();
                }
            }
        }

        /// <summary>
        /// Resets user password. If <see cref="UserModel.Password"/> is null
        /// it generates a <see cref="RandomString"/> for the password.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="accessBy"></param>
        /// <returns>The the new password</returns>
        public async Task<string> ResetPassword(UserModel model, Guid accessBy)
        {
            using (var conn = Connection)
            {
                //Generate RSA keys for JWTs
                var csp = RSA.Create(2048);
                var publicKey = csp.ExportParameters(false);
                var privateKey = csp.ExportParameters(true);
                var pass = RandomString();

                if (model.Password != null)
                {
                    pass = model.Password;
                }

                var password = AuthenticationHelper.HashPassword(pass);

                await conn.ExecuteAsync(
                    "UpdateResetPassword",
                    new
                    {
                        p_email = model.Email,
                        p_password = password,
                        p_publicKey = AuthenticationHelper.SerializeRSAKey(publicKey),
                        p_privateKey = AuthenticationHelper.SerializeRSAKey(privateKey),
                    },
                    commandType: CommandType.StoredProcedure
                );

                return pass;
            }
        }

        /// <summary>
        /// Generates a random string to assign a password. The passwords always
        /// starts with RDE27 to ensure the password has an uppercase character 
        /// and a digit.
        /// </summary>
        /// <returns></returns>
        public string RandomString()
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789asdfghjklqwertyuiopzxcvbnm";
            var str =  new string(Enumerable.Repeat(chars, 8)
              .Select(s => s[random.Next(s.Length)]).ToArray());
            return $"RDE27{str}";
        }

        public Task<UserModel> GetAllUsersByService(UserModel model, string service)
        {
            throw new NotImplementedException();
        }
    }
}
