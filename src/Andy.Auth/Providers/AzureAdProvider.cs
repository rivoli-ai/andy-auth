using Andy.Auth.Configuration;
using Andy.Auth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Andy.Auth.Providers;

/// <summary>
/// Authentication provider for Microsoft Azure Active Directory
/// </summary>
public class AzureAdProvider : IAuthProvider
{
    public string Name => "AzureAD";

    public void ConfigureAuthentication(AuthenticationBuilder builder, AndyAuthOptions options)
    {
        if (options.AzureAd == null)
            throw new ArgumentException("AzureAd configuration is required for Azure AD provider");

        if (string.IsNullOrEmpty(options.AzureAd.TenantId))
            throw new ArgumentException("TenantId is required for Azure AD provider");

        if (string.IsNullOrEmpty(options.AzureAd.ClientId))
            throw new ArgumentException("ClientId is required for Azure AD provider");

        var tenantId = options.AzureAd.TenantId;
        var instance = options.AzureAd.Instance ?? "https://login.microsoftonline.com/";
        var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

        builder.AddJwtBearer(options.AuthenticationScheme, jwtOptions =>
        {
            jwtOptions.Authority = authority;
            jwtOptions.Audience = options.AzureAd.ClientId;
            jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                // Azure AD can issue tokens from multiple endpoints
                ValidIssuers = new[]
                {
                    $"{instance.TrimEnd('/')}/{tenantId}/v2.0",
                    $"https://sts.windows.net/{tenantId}/"
                },
                ValidateAudience = true,
                // Azure AD accepts both client ID and api:// format
                ValidAudiences = new[]
                {
                    options.AzureAd.ClientId,
                    $"api://{options.AzureAd.ClientId}"
                },
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                NameClaimType = "preferred_username",
                RoleClaimType = "roles"
            };

            // Apply custom events if provided
            if (options.Events != null)
            {
                jwtOptions.Events = options.Events;
            }
        });
    }

    public Task<UserClaims> GetUserClaimsAsync(ClaimsPrincipal principal)
    {
        // Azure AD uses different claim names than standard OIDC
        var userId = principal.FindFirst("oid")?.Value  // Object ID - unique user identifier
                  ?? principal.FindFirst("sub")?.Value
                  ?? throw new InvalidOperationException("User ID claim (oid) not found in Azure AD token");

        var claims = new UserClaims
        {
            UserId = userId,
            Email = principal.FindFirst("preferred_username")?.Value
                 ?? principal.FindFirst("email")?.Value
                 ?? principal.FindFirst("upn")?.Value,  // User Principal Name
            Name = principal.FindFirst("name")?.Value,
            GivenName = principal.FindFirst("given_name")?.Value,
            FamilyName = principal.FindFirst("family_name")?.Value,
            Picture = null, // Azure AD doesn't include picture in JWT tokens
            AdditionalClaims = new Dictionary<string, string>
            {
                ["tenant_id"] = principal.FindFirst("tid")?.Value ?? string.Empty,
                ["upn"] = principal.FindFirst("upn")?.Value ?? string.Empty,
                ["unique_name"] = principal.FindFirst("unique_name")?.Value ?? string.Empty,
                ["ipaddr"] = principal.FindFirst("ipaddr")?.Value ?? string.Empty
            }
        };

        return Task.FromResult(claims);
    }

    public OAuthMetadata GetOAuthMetadata(AndyAuthOptions options)
    {
        if (options.AzureAd == null || string.IsNullOrEmpty(options.AzureAd.TenantId))
            throw new ArgumentException("AzureAd configuration with TenantId is required");

        var tenantId = options.AzureAd.TenantId;
        var instance = options.AzureAd.Instance ?? "https://login.microsoftonline.com/";
        var authority = new Uri($"{instance.TrimEnd('/')}/{tenantId}/v2.0");

        return new OAuthMetadata
        {
            AuthorizationServer = authority,
            AuthorizationEndpoint = new Uri(authority, "oauth2/v2.0/authorize"),
            TokenEndpoint = new Uri(authority, "oauth2/v2.0/token"),
            RegistrationEndpoint = null, // Azure AD doesn't support dynamic client registration
            ScopesSupported = new[] { "openid", "profile", "email", "offline_access" }
        };
    }
}
