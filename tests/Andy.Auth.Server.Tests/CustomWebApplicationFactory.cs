using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Custom WebApplicationFactory that configures the application for integration testing.
/// Uses Development environment which uses HTTPS on localhost:7088.
/// </summary>
public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
    }
}
