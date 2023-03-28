using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using UserManager.Application.Interfaces;
using UserManager.Application.Models;

namespace UserManager.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }
        [HttpPost("SignUp")]
        public async Task<IActionResult> SignUp(Register model)
        {
            try
            {
                var result = await _userService.RegisterAsync(model);
                if(result.Succeeded)
                {
                    
                    return Ok(result);
                }
                return Conflict(result);
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
    }
}
