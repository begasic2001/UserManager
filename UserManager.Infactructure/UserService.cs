using Azure.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
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
        private readonly TokenValidationParameters tokenValidationParameters;
        
       
        public UserService(
            UserManager<ApplicationUser> userManager, 
            SignInManager<ApplicationUser> signInManager, 
            RoleManager<IdentityRole> roleManager, 
            IConfiguration configuration, 
            TokenValidationParameters tokenValidationParameters
           )
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
            this.roleManager = roleManager;
            this.tokenValidationParameters = tokenValidationParameters;
            
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

        public async Task<string> AddUserToRole(ApplicationUser user, string roleName ) {
            var result = await userManager.AddToRoleAsync(user, roleName);
            return (result.Succeeded) 
                ? $"Success, User has been added to the role" 
                : "User has been added for longtime";   
        }

        public async Task<IdentityResult> RegisterAsync(ApplicationUser user,Register model)
        {
            
            
            var result = await userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                // send otp when login
                //user.TwoFactorEnabled = true;
                var res = await userManager.AddToRoleAsync(user, "User");
                return res;
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
            // check 2fa
            //if (user.TwoFactorEnabled)
            //{
            //    var tokenForF2a = await userManager.GenerateTwoFactorTokenAsync(user, "Email");
            //    var message = new Message(new string[] { user.Email },"OTP Confirmation", tokenForF2a);
                
            //}

            var token = SignInAccessToken(authClaims);
            var refreshToken = SignInRefreshToken(authClaims);
           
            var accessToken =  new JwtSecurityTokenHandler().WriteToken(token);
            var newRefreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken);
            _ = int.TryParse(configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            await userManager.UpdateAsync(user);

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

        public async Task<AuthResult> RefreshToken(string refreshToken)
        {
            var principal = GetPrincipalFromExpiredToken(refreshToken);
            if (principal == null)
            {
                return new AuthResult()
                {
                    AccessToken = "",
                    RefreshToken = "",
                    Error = "Invalid access token or refresh token"
                };
            }
            
            string username = principal.Identity.Name;
            var user = await userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return new AuthResult()
                {
                    AccessToken = "",
                    RefreshToken = "",
                    Error = "Invalid access token or refresh token"
                };
            }

            var newAccessToken = SignInAccessToken(principal.Claims.ToList());
            var newRefreshToken = SignInRefreshToken(principal.Claims.ToList());

            var writeNewAccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken);
            var writeNewRefreshToken = new JwtSecurityTokenHandler().WriteToken(newRefreshToken);
            _ = int.TryParse(configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = writeNewRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            await userManager.UpdateAsync(user);

            var authResponse = new AuthResult()
            {
                AccessToken = writeNewAccessToken,
                RefreshToken = writeNewRefreshToken,
                Error = null
            };
            return authResponse;
        }
        public async Task<IdentityResult> ConfirmEmail(string email, string token)
        {
            var user = await userManager.FindByEmailAsync(email);
            return await userManager.ConfirmEmailAsync(user, token);
        }

   
    //

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {

            tokenValidationParameters.ValidateAudience = false;
            tokenValidationParameters.ValidateIssuer = false;
            tokenValidationParameters.ValidateIssuerSigningKey = true;
            tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:SecretRefresh"]));
            tokenValidationParameters.ValidateLifetime = false;
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters
                , out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken
                || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512Signature, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;

        }
        public async Task<LogoutResult> Logout(string accessToken,string refreshToken)
        {
            var principal = GetPrincipalFromExpiredToken(refreshToken);
            if (principal == null)
            {
                return new LogoutResult()
                {
                    Message = "",
                    Error = "Invalid access token or refresh token"
                };
            }
            string username = principal.Identity.Name;
            var user = await userManager.FindByNameAsync(username);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return new LogoutResult()
                {
                    Message = "",
                    Error = "Invalid access token or refresh token"
                };
            }
            await signInManager.SignOutAsync();
            await userManager.UpdateSecurityStampAsync(user);
            await userManager.RemoveAuthenticationTokenAsync(user, "JWT", accessToken);

            user.RefreshToken = "";
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(0);

            await userManager.UpdateAsync(user);
            return  new LogoutResult()
            {
                Message = "Logout !!!!!",
                Error = "",
            };
            
        }
        //helper
        public async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            var result = await userManager.FindByEmailAsync(email);
            return result;
        }

        public async Task<bool> FindRoleExistAsync(string roleName)
        {
            return await roleManager.RoleExistsAsync(roleName);
        }

        private async Task<List<Claim>> GetAllValidClaims(ApplicationUser user)
        {
            var _options = new IdentityOptions();

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.NameId,user.Id),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Sub,user.Email),
                new Claim(ClaimTypes.Name,user.UserName),
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
        private JwtSecurityToken SignInAccessToken(List<Claim> authClaims)
        {
            var authenKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var accessToken = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authenKey, SecurityAlgorithms.HmacSha512Signature)
            );
            return accessToken;
        }

        private JwtSecurityToken SignInRefreshToken(List<Claim> authClaims)
        {
            var authenKeyRefresh = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:SecretRefresh"]));
            var refreshToken = new JwtSecurityToken(
              issuer: configuration["JWT:ValidIssuer"],
              audience: configuration["JWT:ValidAudience"],
              expires: DateTime.Now.AddDays(7),
              claims: authClaims,
              signingCredentials: new SigningCredentials(authenKeyRefresh, SecurityAlgorithms.HmacSha512Signature)
          );
            return refreshToken;
        }
       
    
    }
}
