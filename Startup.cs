using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Repositories;

namespace rde.edu.do_jericho_walls
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddTransient<IUserRepository, UserRepository>();
            services.AddTransient<IAuthenticationRepository, AuthenticationRepository>();
            services.AddLogging();
            services.AddControllers().AddNewtonsoftJson();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseCors(builder =>
            {
                var cors = Configuration.GetSection("Cors");
                builder.WithOrigins(cors.GetSection("AllowOrigins").Get<string[]>());
                builder.WithHeaders(cors.GetSection("AllowHeaders").Get<string[]>());
                builder.WithMethods(cors.GetSection("AllowMethods").Get<string[]>());
            });
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
