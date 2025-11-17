using Andy.Auth.Configuration;
using Andy.Auth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Andy.Auth.Providers;

/// <summary>
/// Authentication provider for Andy Auth (self-hosted OpenIddict server)
/// </summary>
public class AndyAuthProvider : IAuthProvider
{
    public string Name => "AndyAuth";

    public void ConfigureAuthentication(AuthenticationBuilder builder, AndyAuthOptions options)
    {
        if (string.IsNullOrEmpty(options.Authority))
            throw new ArgumentException("Authority is required for AndyAuth provider. Set AndyAuth:Authority in configuration.");

        builder.AddJwtBearer(options.AuthenticationScheme, jwtOptions =>
        {
            jwtOptions.Authority = options.Authority;
            jwtOptions.Audience = options.Audience;
            jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = options.Authority,
                ValidateAudience = !string.IsNullOrEmpty(options.Audience),  // Validate audience when configured
                ValidAudience = options.Audience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                NameClaimType = ClaimTypes.NameIdentifier,
                RoleClaimType = ClaimTypes.Role
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
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                  ?? principal.FindFirst("sub")?.Value
                  ?? throw new InvalidOperationException("User ID claim not found in token");

        var claims = new UserClaims
        {
            UserId = userId,
            Email = principal.FindFirst(ClaimTypes.Email)?.Value
                 ?? principal.FindFirst("email")?.Value,
            Name = principal.FindFirst(ClaimTypes.Name)?.Value
                ?? principal.FindFirst("name")?.Value,
            GivenName = principal.FindFirst(ClaimTypes.GivenName)?.Value
                     ?? principal.FindFirst("given_name")?.Value,
            FamilyName = principal.FindFirst(ClaimTypes.Surname)?.Value
                      ?? principal.FindFirst("family_name")?.Value,
            Picture = principal.FindFirst("picture")?.Value,
            AdditionalClaims = principal.Claims
                .Where(c => !IsStandardClaim(c.Type))
                .ToDictionary(c => c.Type, c => c.Value)
        };

        return Task.FromResult(claims);
    }

    public OAuthMetadata GetOAuthMetadata(AndyAuthOptions options)
    {
        if (string.IsNullOrEmpty(options.Authority))
            throw new ArgumentException("Authority is required");

        var authority = new Uri(options.Authority);

        return new OAuthMetadata
        {
            AuthorizationServer = authority,
            AuthorizationEndpoint = new Uri(authority, "/connect/authorize"),
            TokenEndpoint = new Uri(authority, "/connect/token"),
            RegistrationEndpoint = new Uri(authority, "/connect/register"),
            ScopesSupported = new[] { "openid", "profile", "email" }
        };
    }

    private static bool IsStandardClaim(string claimType) =>
        claimType is ClaimTypes.NameIdentifier or "sub"
            or ClaimTypes.Email or "email"
            or ClaimTypes.Name or "name"
            or ClaimTypes.GivenName or "given_name"
            or ClaimTypes.Surname or "family_name"
            or "picture" or "aud" or "iss" or "exp" or "nbf" or "iat";
}
