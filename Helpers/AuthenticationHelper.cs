using Microsoft.Extensions.Logging;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Models;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Linq;
using Trivial.Security;
using System.Collections.Generic;

namespace rde.edu.do_jericho_walls.Helpers
{
    public class AuthenticationHelper
    {

        /// <summary>
        /// Convert the given RSAParameters to an XML string. 
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string SerializeRSAKey(RSAParameters key)
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, key);
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(sw.ToString()));
        }

        /// <summary>
        /// Convert the given string to an RSAParameters. 
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RSAParameters DeserializeRSAKey(string key)
        {
            var sr = new StringReader(Encoding.ASCII.GetString(Convert.FromBase64String(key)));
            var xs = new XmlSerializer(typeof(RSAParameters));
            return (RSAParameters)xs.Deserialize(sr);
        }

        /// <summary>
        /// Hash the given password with a salt of 128 and iteration count of 10000.
        /// The hash password is then converted to Base64String where the salt is appended 
        /// to the password hash, e.g salt|hash.
        /// 
        /// The implementation is base on the OWASP .NET: 
        /// https://www.owasp.org/index.php/Using_Rfc2898DeriveBytes_for_PBKDF2
        /// 
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string HashPassword(string password)
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, 128);
            rfc2898DeriveBytes.IterationCount = 10000;
            byte[] hash = rfc2898DeriveBytes.GetBytes(20);
            byte[] salt = rfc2898DeriveBytes.Salt;
            return Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Creates a password hash with the given password and salt
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns>Returns a Base64String password hash</returns>
        public static string HashPasswordWithSalt(string password, string salt)
        {

            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt));
            rfc2898DeriveBytes.IterationCount = 10000;
            byte[] hash = rfc2898DeriveBytes.GetBytes(20);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Creates a new JWT with the given <see cref="AuthenticationJWT"/> as the payload (claim) content.
        /// The expiration time is set to user <see cref="UserModel.TokenDuration"/> hours. The token
        /// is sign with the <see cref="RSASignatureProvider.CreateRS512"/> using the PrivateKey created 
        /// for the user, at user inception.
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <param name="privateKey"></param>
        /// <param name="issuer">Who is issuing this token</param>
        /// <returns>Returns a JWT string sign with the given private key, containing the model as the payload.</returns>
        public static string CreateJWT(UserModel model, string privateKey, string issuer)
        {
            var pri = RSA.Create();
            pri.ImportParameters(DeserializeRSAKey(privateKey));

            var sign = RSASignatureProvider.CreateRS512(pri, needDisposeAlgorithmAutomatically: true);

            var payload = new AuthenticationJWT()
            {
                Issuer = issuer,
                IssuedAt = DateTime.UtcNow,
                Expiration = DateTime.UtcNow.AddHours(model.TokenDuration),
                Payload = model
            };

            var jwt = new JsonWebToken<AuthenticationJWT>(payload, sign);
            return jwt.ToEncodedString();
        }

        /// <summary>
        /// Verifies the given JWT that should be present in the authorization header. Verifies the expiration
        /// time, the issuer and the token signature.
        /// </summary>
        /// 
        /// <param name="authorization">This should be the authorization HTTP header. The helper will do all the parsing.</param>
        /// <param name="repository">An <see cref="IAuthenticationRepository"/> to get the public key of the user and verify the token.</param>
        /// <param name="logger"></param>
        /// <param name="issuer">Who issue the token</param>
        /// <param name="permision">The name of a permission that the user needs to have to fulfill a request.</param>
        /// <returns>Returns an <see cref="AuthorizationModel"/> If the token is valid it will return a instance of the class with the user. But if
        /// the user doesn't has access to the server or the required permission it will set <see cref="AuthorizationModel.Forbiden"/>
        /// to True</returns>
        public static async Task<AuthorizationModel> Authorize(string authorization, IAuthenticationRepository repository, ILogger logger, string issuer, string permision)
        {
            try
            {
                //Check for token in the authorization header
                if (authorization == null) return null;

                var token = authorization.Split("Bearer ")[1];

                if (token == null || (token != null && token.Length < 10)) return null;

                //Get user from claims
                var concreteToken = new JsonWebToken<AuthenticationJWT>.Parser(token);

                if (concreteToken == null) return null;

                var payload = concreteToken.GetPayload();

                if (payload == null) return null;

                var user = payload.Payload;

                if (user == null || (user != null && (user.Id <= 0 || user.Identifier == null || user.Email == null)))
                {
                    return null;
                }

                //Get user public and private keys from database
                var secrets = await repository.GetRSAKeys(user);

                if (secrets == null) return null;
                if (!secrets.Active) return null; //Account is not active

                var pub = new RSACryptoServiceProvider();
                pub.ImportParameters(DeserializeRSAKey(secrets.PublicKey));

                var sign = RSASignatureProvider.CreateRS512(pub,
                    hasPrivateKey: false,
                    needDisposeAlgorithmAutomatically: true
                );

                //Verify token
                if (DateTime.UtcNow >= payload.Expiration)
                {
                    return null;
                }

                if (issuer != payload.Issuer)
                {
                    return null;
                }

                var isValid = concreteToken.Verify(sign, checkName: true);

                if (!isValid)
                {
                    return null;
                }

                //Verify if it has access to the service
                var service = user.ServicePermissions.First(service => service.Name == "jericho-walls");

                if (!service.HasAccess) return new AuthorizationModel()
                {
                    User = user,
                    Forbiden = true
                };

                //Verify if it has the given permission 
                if (permision != null)
                {
                    var perm = service.Permissions.First(permission => permission.Name == permision);

                    if (!perm.HasAccess) return new AuthorizationModel()
                    {
                        User = user,
                        Forbiden = true
                    };
                }

                return new AuthorizationModel()
                {
                    User = user,
                    Forbiden = false
                };
            }
            catch (Exception e)
            {
                logger.LogWarning("Authorizing token throw exception {@Exception} {@StackStace}", e.Message, e.StackTrace);
                return null;
            }
        }

        public static async Task<AuthorizationModel> AuthorizeForProxy(string authorization, IAuthenticationRepository repository, ILogger logger, string issuer, string service)
        {
            try
            {
                //Check for token in the authorization header
                if (authorization == null) return null;

                var token = authorization.Split("Bearer ")[1];

                if (token == null || (token != null && token.Length < 10)) return null;

                //Get user from claims
                var concreteToken = new JsonWebToken<AuthenticationJWT>.Parser(token);

                if (concreteToken == null) return null;

                var payload = concreteToken.GetPayload();

                if (payload == null) return null;

                var user = payload.Payload;

                if (user == null || (user != null && (user.Id <= 0 || user.Identifier == null || user.Email == null)))
                {
                    return null;
                }

                //Get user public and private keys from database
                var secrets = await repository.GetRSAKeys(user);

                if (secrets == null) return null;

                if (!secrets.Active) return null; //Account is not active

                var pub = new RSACryptoServiceProvider();
                pub.ImportParameters(DeserializeRSAKey(secrets.PublicKey));

                var sign = RSASignatureProvider.CreateRS512(pub,
                    hasPrivateKey: false,
                    needDisposeAlgorithmAutomatically: true
                );

                //Verify token
                if (DateTime.UtcNow >= payload.Expiration)
                {
                    return null;
                }

                if (issuer != payload.Issuer)
                {
                    return null;
                }

                var isValid = concreteToken.Verify(sign, checkName: true);

                if (!isValid)
                {
                    return null;
                }

                //Verify if it has access to the service
                var s = user.ServicePermissions.First(s => s.Name == service);

                if (!s.HasAccess) return new AuthorizationModel()
                {
                    User = user,
                    Forbiden = true
                };

                user.Permissions = s.Permissions
                    .Where(p => p.HasAccess == true)
                    .Select(p => p.Name)
                    .ToList();
                user.ServicePermissions = null;

                return new AuthorizationModel()
                {
                    User = user,
                    Forbiden = false
                };
            }
            catch (Exception e)
            {
                logger.LogWarning("Authorizing token throw exception {@Exception} {@StackStace}", e.Message, e.StackTrace);
                return null;
            }
        }
    }
}
