using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Data;

/// <summary>Compatibility registration and one-time cleanup for the Docs SPA.</summary>
public static class AndyDocsWebRegistration
{
    public static async Task SeedAsync(IOpenIddictApplicationManager manager, ILogger logger)
    {
        var legacy = await manager.FindByClientIdAsync("wagram-web");
        if (legacy is not null)
        {
            await manager.DeleteAsync(legacy);
            logger.LogInformation("Deleted legacy OAuth client: wagram-web");
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "andy-docs-web",
            DisplayName = "Andy Docs (web)",
            ClientType = OpenIddictConstants.ClientTypes.Public, // Public client - no secret; PKCE required
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.Endpoints.Token,

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                "scp:urn:andy-docs-api",  // Permission to request andy-docs-api resource

                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            Requirements =
            {
                // Public-client PKCE enforcement (closes part of andy-auth#46 for this client).
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            },
            RedirectUris =
            {
                new Uri("http://localhost:4200/auth/callback"),
                // Local dotnet (canonical port 4202 per andy-service-template/docs/ports.md)
                new Uri("http://localhost:4202/auth/callback"),
                // Docker-compose mode (offset +2000 → port 6202)
                new Uri("http://localhost:6202/auth/callback"),
                // Conductor embedded (unified proxy on 9100, /docs prefix)
                new Uri("http://localhost:9100/docs/auth/callback"),
                // UAT (Vercel-hosted SPA at docs.uat.wagram.ai)
                new Uri("https://docs.uat.wagram.ai/auth/callback"),
                // Production (Vercel-hosted SPA at docs.wagram.ai)
                new Uri("https://docs.wagram.ai/auth/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("http://localhost:4200/"),
                new Uri("http://localhost:4202/"),
                new Uri("http://localhost:6202/"),
                new Uri("http://localhost:9100/docs/"),
                new Uri("https://docs.uat.wagram.ai/"),
                new Uri("https://docs.wagram.ai/")
            }
        };

        var existing = await manager.FindByClientIdAsync("andy-docs-web");
        if (existing is null) await manager.CreateAsync(descriptor);
        else await manager.UpdateAsync(existing, descriptor);
    }
}
