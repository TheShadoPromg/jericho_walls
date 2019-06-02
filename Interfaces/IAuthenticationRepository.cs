using rde.edu.do_jericho_walls.Models;
using System.Threading.Tasks;

namespace rde.edu.do_jericho_walls.Interfaces
{
    public interface IAuthenticationRepository
    {
        Task<AuthenticationSecrets> GetRSAKeys(UserModel model);
        Task<AuthenticationSecrets> ValidatePassword(AuthenticationModel model); 
    }
}
