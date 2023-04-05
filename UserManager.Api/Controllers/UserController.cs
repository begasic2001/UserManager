using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using NETCore.MailKit.Core;
using UserManager.Application.Interfaces;
using UserManager.Application.Models;
using UserManager.Domain.Entities;

namespace UserManager.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IEmailServices _emailService;
        private readonly UserManager<ApplicationUser> _userManager;
        public UserController(IUserService userService , IEmailServices emailService, UserManager<ApplicationUser> userManager)
        {
            _userService = userService;
            _emailService = emailService;
            _userManager = userManager;
        }
        [HttpPost("SignUp")]
        public async Task<IActionResult> SignUp(Register model)
        {
            try
            {
                var user = new ApplicationUser
                {
                    Email = model.Email,
                    UserName = model.Email
                };
                var result = await _userService.RegisterAsync(user,model);
                if (result.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmEmailUrl = Url.Action(nameof(ConfirmMail), "User", new { token, user.Email }, Request.Scheme);
                    var message = new Message(
                        new string[] { user.Email! }, "Confirm email link", confirmEmailUrl);
                    _emailService.SendEmail(message);
                    return StatusCode(StatusCodes.Status200OK,
                        new { 
                            Status = "Success", 
                            Message =$"User has been created & email sent to {user.Email} successfully"
                        });
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new
                        {
                            Status = "Error",
                            Message = "This role doesn't exists"
                        });
                }
            
            }
            catch (Exception ex)
            {
                return Unauthorized(ex.Message);
            }

        }

        [HttpPost("SignIn")]
        public async Task<IActionResult> SignIn(SignIn model)
        {
            try
            {
                var result = await _userService.SignInAsync(model);
                
                return Ok(result);
            }
            catch (Exception ex)
            {
                return Unauthorized(ex.Message);
            }

        }
        [HttpPost("Refresh-Token")]
        public async Task<IActionResult> RefreshToken(ModelToken model)
        {
            try
            {
                if(model.RefreshToken is null)
                {
                    return BadRequest($"Invalid client request {model.RefreshToken}");
                }
                var result = await _userService.RefreshToken(model.RefreshToken);
                return Ok(result);

            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }
        }
        [HttpPost("Role")]
        public async Task<IActionResult> CreateRole(string name)
        {
            try
            {
                var result = await _userService.CreateRole(name);
                return Ok(result);
            }
            catch(Exception ex) {
            
                return BadRequest(ex.Message);
            
            }
          
        }
        [HttpGet("Role")]
        public async Task<IActionResult> Roles()
        {
            try
            {
                var result = await _userService.GetAllRole();
                return Ok(result);
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);

            }
        }

        [HttpGet("GetAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            try
            {
                var result = await _userService.GetAllUser();
                return Ok(result);
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);

            }
        }
        [HttpPost("AddUserToRole")]
        public async Task<IActionResult> AddUserToRole(string email , string roleName)
        {
            try
            {
                var hasUser = await _userService.FindUserByEmailAsync(email);
                if (hasUser == null)
                {
                    return BadRequest(new
                    {
                        error = $"{email} does not exist"
                    });
                }
                var hasRole = await _userService.FindRoleExistAsync(roleName);
                if (!hasRole)
                {
                    return BadRequest(new
                    {
                        error = $"{roleName} does not exist"
                    });
                }
                var result = await _userService.AddUserToRole(hasUser, roleName);
                return Ok(result);
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }
            
        }
        [HttpGet("GetUserRole")]
        public async Task<IActionResult> GetUserRole(string email)
        {
            try
            {
                var hasUser = await _userService.FindUserByEmailAsync(email);
                if (hasUser == null)
                {
                    return BadRequest(new
                    {
                        error = $"{email} does not exist"
                    });
                }

                var roles = await _userService.GetUserRole(hasUser);
                return Ok(roles);
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }
          
        }

        [HttpPost("RemoveUserRole")]
        public async Task<IActionResult> RemoveUserToRole(string email, string roleName)
        {
            try
            {
                var hasUser = await _userService.FindUserByEmailAsync(email);
                if (hasUser == null)
                {
                    return BadRequest(new
                    {
                        error = $"{email} does not exist"
                    });
                }
                var hasRole = await _userService.FindRoleExistAsync(roleName);
                if (!hasRole)
                {
                    return BadRequest(new
                    {
                        error = $"{roleName} does not exist"
                    });
                }
                var result = await _userService.RemoveUserRole(hasUser, roleName);
                if (result.Succeeded)
                {
                    return Ok(new
                    {
                        result = $"User {email} has been removed from role {roleName}"
                    });
                }
                return BadRequest(new
                {
                    error = $"Unable to remove User {email} from role {roleName}"
                });
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }

        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User")]
        [HttpPost("Logout")]
        public async Task<IActionResult> Logout(ModelToken model)
        {
            if (model.RefreshToken is null)
            {
                return BadRequest($"Invalid client request {model.RefreshToken}");
            }
            else
            {
                var accessToken = HttpContext.Request.Headers["Authorization"].ToString().Split()[1];
                var result = await _userService.Logout(accessToken, model.RefreshToken);
                return Ok(result);
            }
            
        }

        [HttpGet("ConfirmMail")]
        public  async Task<IActionResult> ConfirmMail(string email, string token)
        {
            try
            {
                var result = await _userService.ConfirmEmail(email, token);
                if(result.Succeeded)
                {
                    
                    return Ok(result);  
                }
                return BadRequest(result);
            }
            catch (Exception ex)
            {
                return BadRequest($"{ex.Message}");
                
            }
            
        }
    }
}
