using UserManager.Domain.Entities;

namespace UserManager.Api.Controllers
{
    public class AppUser
    {
        public ApplicationUser UserName { get; set; }
        public ApplicationUser Email { get; set; }
    }
}
