using Microsoft.Extensions.Configuration;
using MySql.Data.MySqlClient;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using Dapper;
using System;
using System.Security.Cryptography;
using rde.edu.do_jericho_walls.Helpers;

namespace rde.edu.do_jericho_walls.Repositories
{
    public class ServiceRepository : IServiceRepository
    {
        private readonly IConfiguration config;

        public ServiceRepository(IConfiguration config)
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
        /// Get all services created.
        /// </summary>
        /// <returns>A IList of <see cref="ServiceModel"/></returns>
        public async Task<IList<ServiceModel>> GetAll()
        {
            using (var conn = Connection)
            {
                var services = new Dictionary<int, ServiceModel>();

                var result = await conn.QueryAsync<ServiceModel, string, ServiceModel>(
                    "ReadAllServices",
                    map: (service, permission) =>
                    {
                        if (!services.TryGetValue(service.Id, out ServiceModel serv))
                        {
                            serv = service;
                            services.Add(serv.Id, serv);
                        }

                        serv.Permissions.Add(permission);

                        return serv;
                    },
                    splitOn: "permission",
                    commandType: CommandType.StoredProcedure
                );

                return result.Distinct().ToList();
            }
        }

        /// <summary>
        /// Created a new service
        /// </summary>
        /// <param name="model"></param>
        /// <param name="accessBy"></param>
        /// <returns></returns>
        public async Task<ServiceModel> Create(ServiceModel model, Guid accessBy)
        {
            using (var conn = Connection)
            {
                //Generate GUID for the database service registry
                var guid = Guid.NewGuid();

                //Generate RSA keys for service communication
                var csp = RSA.Create(2048);
                var publicKey = csp.ExportParameters(false);
                var privateKey = csp.ExportParameters(true);
                var pub = AuthenticationHelper.SerializeRSAKey(publicKey);

                //Create service registry
                var id = await conn.QueryFirstAsync<int>("CreateService",
                    new
                    {
                        p_identifier = guid,
                        p_name = model.Name,
                        p_description = model.Description,
                        p_host = model.Host,
                        p_port = model.Port,
                        p_publicKey = pub,
                        p_privateKey = AuthenticationHelper.SerializeRSAKey(privateKey),
                        p_active = model.Active,
                        p_UserIdentifier = accessBy,
                        p_recordBy = config.GetValue<string>("SystemName"),
                    },
                    commandType: CommandType.StoredProcedure
                );

                model.Id = id;
                model.Identifier = guid;
                model.PublicKey = pub;
                return model;
            }
        }

        /// <summary>
        /// Updates the information of the given service
        /// </summary>
        /// <param name="model"></param>
        /// <param name="accessBy"></param>
        /// <returns></returns>
        public async Task Update(ServiceModel model, Guid accessBy)
        {
            using (var conn = Connection)
            {
                await conn.ExecuteAsync(
                       "UpdateService",
                       new
                       {
                           p_identifier = model.Identifier,
                           p_description = model.Description,
                           p_host = model.Host,
                           p_port = model.Port,
                           p_active = model.Active,
                           p_userIdentifier = accessBy,
                           p_recordBy = config.GetValue<string>("SystemName")
                       },
                       commandType: CommandType.StoredProcedure
                   );
            }
        }
    }
}
