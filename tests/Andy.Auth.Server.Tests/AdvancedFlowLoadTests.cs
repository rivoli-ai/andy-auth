using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Andy.Auth.Server.Tests;

public sealed class AdvancedFlowLoadTests
{
    [Theory]
    [InlineData("device")]
    [InlineData("par")]
    public async Task ConcurrentRequests_CreateDistinctBoundedNativeArtifacts(string flow)
    {
        using var factory = new LoadFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        using (var scope = factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "load-client", ClientType = ClientTypes.Public, ConsentType = ConsentTypes.Explicit,
                RedirectUris = { new Uri("http://localhost:4321/callback") },
                Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.PushedAuthorization,
                    Permissions.Endpoints.Token, Permissions.Endpoints.DeviceAuthorization,
                    Permissions.GrantTypes.DeviceCode, Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code }
            });
        var responses = await Task.WhenAll(Enumerable.Range(0, 24).Select(index =>
        {
            var form = new Dictionary<string, string> { ["client_id"] = "load-client", ["scope"] = "openid" };
            if (flow == "par")
            {
                form["response_type"] = "code";
                form["redirect_uri"] = "http://localhost:4321/callback";
                form["state"] = index.ToString();
                form["code_challenge_method"] = "S256";
                form["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(new string('v', 43))));
            }
            return client.PostAsync("/connect/" + flow, new FormUrlEncodedContent(form));
        }));
        try
        {
            var identifiers = new HashSet<string>();
            foreach (var response in responses)
            {
                Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert.True(identifiers.Add(body.RootElement.GetProperty(flow == "par" ? "request_uri" : "device_code").GetString()!));
                Assert.InRange(body.RootElement.GetProperty("expires_in").GetInt32(), 1, flow == "par" ? 90 : 600);
            }
            Assert.Equal(24, identifiers.Count);
        }
        finally { foreach (var response in responses) response.Dispose(); }
    }
    private sealed class LoadFactory : CustomWebApplicationFactory
    {
        private readonly string? prior = Environment.GetEnvironmentVariable("OpenIddict__AdvancedFlows__PAR__Enabled");
        public LoadFactory() => Environment.SetEnvironmentVariable("OpenIddict__AdvancedFlows__PAR__Enabled", "true");
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services => services.Configure<IpRateLimitOptions>(options => options.GeneralRules = new()));
        }
        protected override void Dispose(bool disposing)
        {
            Environment.SetEnvironmentVariable("OpenIddict__AdvancedFlows__PAR__Enabled", prior);
            base.Dispose(disposing);
        }
    }
}
