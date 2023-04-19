using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UserManager.Application.Models;
using UserManager.Domain.Entities;

namespace UserManager.Application.Interfaces
{
    public interface IUserService
    {
        Task<IdentityResult> RegisterAsync(ApplicationUser user,Register model);
        Task<AuthResult> SignInAsync(SignIn model);
        Task<List<IdentityRole>> GetAllRole();
        Task<List<ApplicationUser>> GetAllUser();
        Task<string> CreateRole(string name);

        Task<ApplicationUser> FindUserByEmailAsync(string email);
        Task<bool> FindRoleExistAsync(string roleName);
        Task<string> AddUserToRole(ApplicationUser user, string roleName);
        Task<ICollection<string>> GetUserRole(ApplicationUser user);
        Task<IdentityResult> RemoveUserRole(ApplicationUser user, string roleName);
        Task<AuthResult> RefreshToken(string refreshToken);
        Task<LogoutResult> Logout(string accessToken,string refreshToken);
        Task<IdentityResult> ConfirmEmail(string email, string token);
        Task<AuthResult> SignInOtpEmail(string code, string email);
    }
}
