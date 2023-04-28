
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using UserManager.Application.Interfaces;
using UserManager.Application.Models;
using UserManager.Domain.Entities;
using Microsoft.AspNetCore.Authentication.Facebook;
using RestSharp;
using System.Text.Json;
using System;
using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

namespace UserManager.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly IUserService _userService;
        private readonly IEmailServices _emailService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        public UserController(IUserService userService, IEmailServices emailService, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userService = userService;
            _emailService = emailService;
            _userManager = userManager;
            this.signInManager = signInManager;
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
                var result = await _userService.RegisterAsync(user, model);
                if (result.Succeeded)
                {

                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmEmailUrl = Url.Action(nameof(ConfirmMail), "User", new { token, user.Email }, Request.Scheme);
                    var message = new Message(
                        new string[] { user.Email! }, "Confirm email link", confirmEmailUrl);
                    _emailService.SendEmail(message);
                    return StatusCode(StatusCodes.Status200OK,
                        new
                        {
                            Status = "Success",
                            Message = $"User has been created & email sent to {user.Email} successfully"
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
        //[HttpPost("SignIn-2FA")]
        //public async Task<IActionResult> SignIn_2FA()
        //{
        //if (user.TwoFactorEnabled)
        //{
        //    return StatusCode(StatusCodes.Status200OK,
        //    new
        //    {
        //        Status = "Success",
        //        Message = $"We have sent an OTP {user.Email} "
        //    });
        //}
        //}
        [HttpPost("Refresh-Token")]
        public async Task<IActionResult> RefreshToken(ModelToken model)
        {
            try
            {
                if (model.RefreshToken is null)
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
            catch (Exception ex)
            {

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
        public async Task<IActionResult> AddUserToRole(string email, string roleName)
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
        public async Task<IActionResult> ConfirmMail(string email, string token)
        {
            try
            {
                var result = await _userService.ConfirmEmail(email, token);
                if (result.Succeeded)
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

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPassworkLink = Url.Action(nameof(GetResetPassword), "User", new { token, user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot password link", forgotPassworkLink);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                       new
                       {
                           Status = "Success",
                           Message = $"Password changed request is send on email {user.Email}, Please open your email & click the link"

                       });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                       new
                       {
                           Status = "Error",
                           Message = "Couldn't send link to email, please try again"
                       });
        }


        [HttpGet("reset-password")]

        public async Task<IActionResult> GetResetPassword(string token, string email)
        {
            var model = new ResetPassword
            {
                Token = token,
                Email = email
            };

            return Ok(new { model });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                       new
                       {
                           Status = "Success",
                           Message = $"Password has been changed "

                       });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                       new
                       {
                           Status = "Error",
                           Message = "Couldn't send link to email, please try again"
                       });
        }

        [HttpGet("GetUserByEmail")]
        public async Task<IActionResult> GetUserByEmail(string email)
        {
            try
            {
                var result = await _userService.FindUserByEmailAsync(email);
                return Ok(result);
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }
        }

        [HttpPost("LoginWith2FA")]
        public async Task<IActionResult> LoginWith2FA(string code, string email)
        {
            try
            {
                var result = await _userService.SignInOtpEmail(code, email);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // google

        [AllowAnonymous]
        [HttpGet("LoginWithGoogle")]
        public IActionResult GoogleLogin()
        {
            string redirectUrl = Url.Action("GoogleResponse", "User");
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
        }

        [AllowAnonymous]
        [HttpGet("GoogleResponse")]
        public async Task<IActionResult> GoogleResponse()
        {
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return BadRequest("No Response");
            }
            return Ok(info);
            //var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,isPersistent: false);

            //string[] userInfo = {
            //    info.Principal.FindFirst(ClaimTypes.Name)!.Value,
            //    info.Principal.FindFirst(ClaimTypes.Email)!.Value,

            //};
            //if (result.Succeeded)
            //{
            //    return Ok(userInfo);
            //}
            //else
            //{
            //    var user = new ApplicationUser
            //    {
            //        Email = info.Principal.FindFirst(ClaimTypes.Email).Value,
            //        UserName = info.Principal.FindFirst(ClaimTypes.Email).Value
            //    };
            //    // find user
            //    var hasUser = await _userManager.FindByEmailAsync(user.Email);
             


            //    IdentityResult identResult = await _userManager.CreateAsync(user);
            //    if (identResult.Succeeded)
            //    {
            //        identResult = await _userManager.AddLoginAsync(user, info);
            //        if (identResult.Succeeded)
            //        {
            //            await signInManager.SignInAsync(user, isPersistent:false);
            //            return Ok(result);
            //        }
            //    }
            //    return NoContent();
            //}
        }
        // facebook
        [AllowAnonymous]
        [HttpGet("LoginWithFacebook")]
        public IActionResult FaceBookLogin()
        {
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Facebook", Url.Action("FacbookResponse", "User"));
            return new ChallengeResult("Facebook", properties);
        }

        [HttpGet("FacbookResponse")]
        public async Task<IActionResult> FacbookResponse()
        {
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            var access_token = info.AuthenticationTokens.First().Value;
            var client = new RestClient("https://graph.facebook.com/v16.0");
            var request = new RestRequest($"me?access_token={access_token}&fields=picture");
            var response = await client.GetAsync(request);
            return Ok(response);
        }
    }
}

