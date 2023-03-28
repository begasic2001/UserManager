using Azure.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using UserManager.Application.Interfaces;
using UserManager.Application.Models;
using UserManager.Domain.Entities;

namespace UserManager.Infactructure
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IConfiguration configuration;
        private readonly RoleManager<IdentityRole> roleManager;
        public UserService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
            this.roleManager = roleManager;
        }

        public async Task<string> CreateRole(string name)
        {
            var roleExists = await roleManager.RoleExistsAsync(name);
            if (!roleExists)
            {
                var roleResult = await roleManager.CreateAsync(new IdentityRole(name));
                if (roleResult.Succeeded)
                {
                    return $"The role {name} has been added succesfully!";
                }
            }
            return $"The role {name} has been exists!";

        }

        public async Task<List<IdentityRole>> GetAllRole()
        {
            var roles = await roleManager.Roles.ToListAsync();
            return roles;
        }

        public async Task<List<ApplicationUser>> GetAllUser()
        {
            var users = await userManager.Users.ToListAsync();
            return users;
        }

        public async Task<string> AddUserToRole(ApplicationUser user , string roleName) {
            var result = await userManager.AddToRoleAsync(user, roleName);
            return (result.Succeeded) 
                ? $"Success, User has been added to the role" 
                : "User has been added for longtime";   
        }

        public async Task<IdentityResult> RegisterAsync(Register model)
        {
            var user = new ApplicationUser
            {
                Email = model.Email,
                UserName = model.Email
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return await userManager.AddToRoleAsync(user, "User");
            }
            else
            {
                return result;
            }
        }

        public async Task<AuthResult> SignInAsync(SignIn model)
        {
            var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
            if (!result.Succeeded)
            {
                return new AuthResult()
                {
                    AccessToken = "",
                    RefreshToken = "",
                    Error = result.ToString()
                }; 
            }
            var user = await userManager.FindByEmailAsync(model.Email);
            // get all claim in method helper
            var claims = await GetAllValidClaims(user);

            var authClaims = new List<Claim>(claims);

            var authenKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var authenKeyRefresh = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:SecretRefresh"]));
            var token = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authenKey, SecurityAlgorithms.HmacSha512Signature)
            );

            var refreshToken = new JwtSecurityToken(
               issuer: configuration["JWT:ValidIssuer"],
               audience: configuration["JWT:ValidAudience"],
               expires: DateTime.Now.AddDays(7),
               claims: authClaims,
               signingCredentials: new SigningCredentials(authenKeyRefresh, SecurityAlgorithms.HmacSha512Signature)
           );
            var accessToken =  new JwtSecurityTokenHandler().WriteToken(token);
            var newRefreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken);
            var authResponse = new AuthResult()
            {
                AccessToken = accessToken,
                RefreshToken = newRefreshToken,
                Error = null
            };
            return authResponse;
        }
        public async Task<ICollection<string>> GetUserRole(ApplicationUser user)
        {
           return await userManager.GetRolesAsync(user);
        }

        public async Task<IdentityResult> RemoveUserRole(ApplicationUser user,string roleName)
        {
            return await userManager.RemoveFromRoleAsync(user, roleName);
        }

        //public async Task<AuthResult> RefreshToken()
        //{

        //}

        //helper
        public async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            return await userManager.FindByEmailAsync(email);
        }

        public async Task<bool> FindRoleExistAsync(string roleName)
        {
            return await roleManager.RoleExistsAsync(roleName);
        }

       private async Task<List<Claim>> GetAllValidClaims(ApplicationUser user)
        {
            var _options = new IdentityOptions();

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            // get the claim assigned
            var userClaims = await userManager.GetClaimsAsync(user);
            claims.AddRange(userClaims);

            // get user rold add to the claims
            var userRoles = await userManager.GetRolesAsync(user);

            foreach (var userRole in userRoles)
            {
                var role = await roleManager.FindByNameAsync(userRole);

                if(role != null)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole));
                    var roleClaims = await roleManager.GetClaimsAsync(role);
                    foreach (var roleClaim in roleClaims)
                    {
                        claims.Add(roleClaim);
                    }
                }
            }

            return claims;
        }
    }
}
