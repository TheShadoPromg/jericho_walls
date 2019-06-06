using rde.edu.do_jericho_walls.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace rde.edu.do_jericho_walls.Interfaces
{
    public interface IUserRepository
    {
        Task<UserModel> GetById(int id);
        Task<IList<UserModel>> GetAll();
        Task<UserModel> Create(UserModel model);
        Task Updated(UserModel model, Guid accessBy);
        Task<string> ResetPassword(UserModel model, Guid accessBy);

        Task<UserModel> GetAllUsersByService(UserModel model, string service);
    }
}
