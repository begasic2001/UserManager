using Autofac.Core;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.Extensions.Configuration;
using UserManager.Application.Models;
using UserManager.Infactructure;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
//builder.Services.AddRazorPages();
builder.Services.AddControllers();
//builder.Services.AddControllersWithViews();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Host.AddHostBuild();

builder.Services.AddServiceCollection(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
//app.UseStaticFiles();
app.UseCookiePolicy();
//app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
//app.MapRazorPages();

app.Run();
