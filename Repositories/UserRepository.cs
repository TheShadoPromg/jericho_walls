﻿using Microsoft.Extensions.Configuration;
using MySql.Data.MySqlClient;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using System.Security.Cryptography;
using System;
using rde.edu.do_jericho_walls.Helpers;

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
            return await Connection.QueryFirstOrDefaultAsync<UserModel>(
                "ReadUser",
                new { p_id = id},
                commandType: CommandType.StoredProcedure
            );
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
            //Generate GUID for the database user registry
            var guid = Guid.NewGuid();

            //Generate RSA keys for JWTs
            var csp = RSA.Create(2048);
            var publicKey = csp.ExportParameters(false);
            var privateKey = csp.ExportParameters(true);

            //Create user registry
            var id = await Connection.QueryFirstAsync<int>("CreateUser",
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
                    p_recordBy = config.GetValue<string>("SystemName"),
                },
                commandType: CommandType.StoredProcedure
            );

            model.Id = id;
            model.Identifier = guid;
            return model;
        }

    }
}