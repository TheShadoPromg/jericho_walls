using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Serilog;
using Serilog.Sinks.Loki;
using Serilog.Sinks.Loki.Labels;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Collections.Generic;

namespace rde.edu.do_jericho_walls
{
    public class Program
    {
        public class LogLabelProvider : ILogLabelProvider
        {
            public IList<LokiLabel> GetLabels()
            {
                return new List<LokiLabel>
            {
                new LokiLabel("app", "jericho_walls"),
            };
            }
        }

        public static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .Enrich.FromLogContext()
                .WriteTo.Console(theme: AnsiConsoleTheme.Literate)
                .WriteTo.LokiHttp(new NoAuthCredentials("http://172.16.0.50:3100"), new LogLabelProvider())
                .CreateLogger();

            try
            {
                Log.Information("Starting web host");
                BuildWebHost(args).Run();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseSerilog()
                .Build();
    }
}
