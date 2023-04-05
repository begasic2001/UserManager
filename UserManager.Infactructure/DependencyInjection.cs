
using Autofac;
using Autofac.Core;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json.Serialization;
using UserManager.Application.Interfaces;
using UserManager.Application.Models;
using UserManager.Domain.Entities;
using UserManager.Infactructure.Data;


namespace UserManager.Infactructure
{
    public static class DependencyInjection
    {
        public static IHostBuilder AddHostBuild(this IHostBuilder hostBuilder)
        {
            hostBuilder.UseServiceProviderFactory(new AutofacServiceProviderFactory());
            hostBuilder.ConfigureContainer<ContainerBuilder>(autofacConfigure =>
            {
                autofacConfigure.
                        RegisterType<UserService>().As<IUserService>();
                autofacConfigure.
                        RegisterType<TokenValidationParameters>();
                autofacConfigure.
                        RegisterType<EmailServices>().As<IEmailServices>();
                //autofacConfigure.
                //        Register(c => c.Resolve<EmailConfiguration>());
            });
            return hostBuilder;
        }

        public static IServiceCollection AddServiceCollection(this IServiceCollection services, Microsoft.Extensions.Configuration.ConfigurationManager configuration)
        {
            services.AddCors(options => options.AddDefaultPolicy(policy =>
                    policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod())
            );
            services.AddMvc()
                    .AddJsonOptions(x => x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);
            services.AddIdentity<ApplicationUser, IdentityRole>()
                    .AddEntityFrameworkStores<UserManagerContext>().AddDefaultTokenProviders();
            // add config email service set up
            services.Configure<IdentityOptions>(options => options.SignIn.RequireConfirmedEmail = true);
            
            services.AddDbContext<UserManagerContext>(option =>
            {
                option.UseSqlServer(configuration.GetConnectionString("DefaultString"), b => b.MigrationsAssembly("UserManager.Api"));

            });
            var tokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                //RequireExpirationTime = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = configuration["JWT:ValidAudience"],
                ValidIssuer = configuration["JWT:ValidIssuer"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]))
            };
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = tokenValidationParameters;
            });

            // Add Email Config
            var emailConfig = configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
            services.AddSingleton(emailConfig);
            return services;
        }
    }
}
