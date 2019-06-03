using rde.edu.do_jericho_walls.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace rde.edu.do_jericho_walls.Interfaces
{
    public interface IServiceRepository
    {
        Task<IList<ServiceModel>> GetAll();
        Task<ServiceModel> Create(ServiceModel model, Guid accessBy);
        Task Update(ServiceModel model, Guid accessBy);
    }
}
