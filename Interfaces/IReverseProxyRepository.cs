using rde.edu.do_jericho_walls.Models;
using System.Threading.Tasks;

namespace rde.edu.do_jericho_walls.Repositories
{
    public interface IReverseProxyRepository
    {
        Task<ServiceModel> GetByName(string name);
    }
}
