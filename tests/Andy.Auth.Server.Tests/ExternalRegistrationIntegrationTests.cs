using System.Text.Json;
using Andy.Auth.Server.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests;

public sealed class ExternalRegistrationIntegrationTests
{
    private static readonly string[] Clients = ["andy-docs-web", "claude-desktop", "chatgpt", "cline", "roo", "kilocode", "continue-dev",
        "conductor-mac", "andy-agentic-web", "andy-subscription-web", "andy-subscription-cli", "andy-narration-web"];

    [Fact]
    public async Task EveryBundledClientIsCreatedAndReseedingPreservesIdentitiesAndGrants()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var ids = new Dictionary<string, string>();
        foreach (var client in Clients)
        {
            var application = await manager.FindByClientIdAsync(client);
            Assert.NotNull(application);
            ids[client] = (await manager.GetIdAsync(application))!;
        }
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var authorization = await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
            { ApplicationId = ids["claude-desktop"], Subject = DbSeeder.TestUserWellKnownId, Status = "valid", Type = "permanent" });
        var grantId = (await authorizations.GetIdAsync(authorization))!;
        var seeder = ActivatorUtilities.CreateInstance<DbSeeder>(scope.ServiceProvider);
        await seeder.SeedFromManifestsAsync();
        foreach (var client in Clients)
            Assert.Equal(ids[client], await manager.GetIdAsync((await manager.FindByClientIdAsync(client))!));
        Assert.NotNull(await authorizations.FindByIdAsync(grantId));
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        Assert.NotNull(await scopes.FindByNameAsync("urn:andy-narration-api"));
        Assert.NotNull(await scopes.FindByNameAsync("urn:andy-subscription-api"));
    }

    [Fact]
    public async Task ExplicitClientManifestWinsOverBundledDefaultsWithoutChangingIdentity()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var originalId = await manager.GetIdAsync((await manager.FindByClientIdAsync("claude-desktop"))!);
        var file = Path.Combine(Path.GetTempPath(), "andy-external-override-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            await File.WriteAllTextAsync(file, JsonSerializer.Serialize(new
            {
                service = new { name = "deployment-claude", displayName = "Deployment Claude" },
                auth = new { audience = "urn:andy-docs-api", registerAudience = false,
                    webClient = new { clientId = "claude-desktop", clientType = "public", displayName = "Deployment Claude",
                        grantTypes = new[] { "authorization_code" }, redirectUris = new[] { "https://consumer.example/callback" } } }
            }));
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
                { ["Registrations:ManifestPaths:0"] = file }).Build();
            var seeder = ActivatorUtilities.CreateInstance<DbSeeder>(scope.ServiceProvider, config);
            await seeder.SeedFromManifestsAsync();
            var application = (await manager.FindByClientIdAsync("claude-desktop"))!;
            Assert.Equal(originalId, await manager.GetIdAsync(application));
            Assert.Equal("Deployment Claude", await manager.GetDisplayNameAsync(application));
            Assert.Equal(new[] { "https://consumer.example/callback" }, await manager.GetRedirectUrisAsync(application));
        }
        finally { File.Delete(file); }
    }
}
