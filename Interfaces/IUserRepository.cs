using rde.edu.do_jericho_walls.Models;
using System.Threading.Tasks;

namespace rde.edu.do_jericho_walls.Interfaces
{
    public interface IUserRepository
    {
        Task<UserModel> GetById(int id);
        Task<UserModel> Create(UserModel model);
    }
}
