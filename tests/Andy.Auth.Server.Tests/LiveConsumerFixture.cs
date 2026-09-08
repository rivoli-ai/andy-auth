using Andy.Auth.Extensions;
using Andy.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Server;

namespace Andy.Auth.Server.Tests;

/// <summary>A separate protected resource using the public Andy.Auth consumer library.</summary>
internal static class LiveConsumerFixture
{
    public static Task<IHost> StartAsync(CustomWebApplicationFactory authority, JsonWebToken token) =>
        new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddAndyAuth(options =>
            {
                options.Authority = token.Issuer;
                options.Audience = token.Audiences.First();
                options.RequireLiveSession = true;
            });
            services.AddHttpClient(LiveSessionValidation.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => authority.Server.CreateHandler());
            services.PostConfigure<JwtBearerOptions>("Bearer", options =>
            {
                var metadata = new OpenIdConnectConfiguration { Issuer = token.Issuer };
                foreach (var credential in authority.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue.SigningCredentials)
                    metadata.SigningKeys.Add(credential.Key);
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata);
            });
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapGet("/sensitive", context => context.Response.WriteAsync("allowed"))
                .RequireAuthorization());
        })).StartAsync();
}
