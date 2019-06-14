using System;
using System.Data;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using MySql.Data.MySqlClient;
using rde.edu.do_jericho_walls.Models;
using Dapper;

namespace rde.edu.do_jericho_walls.Repositories
{
    public class ReverseProxyRepository : IReverseProxyRepository
    {
        private readonly IConfiguration config;

        public ReverseProxyRepository(IConfiguration config)
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
        /// Gets a <see cref="ServiceModel"/> from the given name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<ServiceModel> GetByName(string name)
        {
            using (var conn = Connection)
            {
                var result = await conn.QueryFirstOrDefaultAsync<ServiceModel>(
                    "ReadServiceByName",
                    new
                    {
                        p_name = name,
                    },
                    commandType: CommandType.StoredProcedure
                );

                return result;
            }
        }
    }
}
