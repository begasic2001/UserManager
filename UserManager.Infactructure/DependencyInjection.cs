
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using UserManager.Application.Interfaces;
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
                //autofacConfigure.
                //    RegisterType<AuthenticationApp>().As<IAuthentication>();
                //autofacConfigure.
                //    RegisterType<JwtTokenGenerator>().As<IJwtTokenGenerator>();
                //autofacConfigure.
                //    RegisterType<DateTimeProvider>().As<IDateTimeProvider>();
                autofacConfigure.
                        RegisterType<UserService>().As<IUserService>();
            });
            return hostBuilder;
        }

        public static IServiceCollection AddServiceCollection(this IServiceCollection services, Microsoft.Extensions.Configuration.ConfigurationManager configuration)
        {
            services.AddIdentity<ApplicationUser, IdentityRole>()
                    .AddEntityFrameworkStores<UserManagerContext>().AddDefaultTokenProviders();
            services.AddDbContext<UserManagerContext>(option =>
            {
                option.UseSqlServer(configuration.GetConnectionString("DefaultString"), b => b.MigrationsAssembly("UserManager.Api"));

            });
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuerSigningKey= true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = configuration["JWT:ValidAudience"],
                    ValidIssuer = configuration["JWT:ValidIssuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]))
                };
            });
            return services;
        }
    }
}
