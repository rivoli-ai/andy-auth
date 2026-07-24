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

        // Build list of valid audiences (primary + additional)
        var validAudiences = new List<string>();
        if (!string.IsNullOrEmpty(options.Audience))
            validAudiences.Add(options.Audience);
        if (options.ValidAudiences != null)
            validAudiences.AddRange(options.ValidAudiences.Where(a => !string.IsNullOrEmpty(a)));

        // Fail fast rather than quietly turning audience validation off.
        // The previous `ValidateAudience = validAudiences.Count > 0` meant an
        // unconfigured consumer accepted *any* token this authority minted —
        // including one issued for a different API in the same fleet, which is
        // a confused-deputy path on a shared IdP (andy-auth#148). Nothing
        // logged, nothing threw; it just silently trusted everything.
        if (validAudiences.Count == 0)
        {
            throw new ArgumentException(
                "AndyAuth:Audience (or AndyAuth:ValidAudiences) is required for the AndyAuth provider. " +
                "Without it, every token issued by this authority would be accepted, including tokens " +
                "minted for other APIs.");
        }

        // Self-signed certificates on the metadata/JWKS backchannel are a
        // development affordance, and a separate decision from allowing
        // plain-HTTP metadata — see AllowInvalidBackchannelCertificates.
        // Checked here rather than inside the AddJwtBearer callback so a
        // misconfiguration fails at startup instead of on the first token.
        if (options.AllowInvalidBackchannelCertificates && IsProductionEnvironment())
        {
            throw new InvalidOperationException(
                "AndyAuth:AllowInvalidBackchannelCertificates cannot be enabled in Production. " +
                "Disabling certificate validation on the JWKS backchannel allows a MITM to " +
                "serve substitute signing keys.");
        }

        builder.AddJwtBearer(options.AuthenticationScheme, jwtOptions =>
        {
            jwtOptions.Authority = options.Authority;
            jwtOptions.Audience = options.Audience;
            jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

            if (options.AllowInvalidBackchannelCertificates)
            {
                jwtOptions.BackchannelHttpHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };
            }

            // Accept both trailing-slash and no-trailing-slash issuer formats
            // OpenIddict uses trailing slash, Duende does not by default
            var authorityBase = options.Authority.TrimEnd('/');
            var validIssuers = new[] { authorityBase, authorityBase + "/" };

            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = validIssuers,
                ValidateAudience = true,
                ValidAudiences = validAudiences,
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

        // Resolve endpoints *relative* to the authority so a path-prefixed
        // deployment keeps its prefix. A rooted path ("/connect/authorize")
        // discards it, so an authority of "http://localhost:9100/auth/" —
        // exactly how Conductor's unified proxy exposes this server — yielded
        // "http://localhost:9100/connect/authorize" and every endpoint was
        // wrong (andy-auth#148). Uri resolution also drops the last segment of
        // a base without a trailing slash, so normalize that first.
        var authority = new Uri(
            options.Authority.EndsWith('/') ? options.Authority : options.Authority + "/");

        return new OAuthMetadata
        {
            AuthorizationServer = authority,
            AuthorizationEndpoint = new Uri(authority, "connect/authorize"),
            TokenEndpoint = new Uri(authority, "connect/token"),
            RegistrationEndpoint = new Uri(authority, "connect/register"),
            ScopesSupported = new[] { "openid", "profile", "email" }
        };
    }

    /// <summary>
    /// Best-effort environment probe for the guard on
    /// <see cref="AndyAuthOptions.AllowInvalidBackchannelCertificates"/>.
    /// The library has no <c>IHostEnvironment</c> to consult here — providers
    /// are constructed before the host is built — so it reads the same
    /// variables ASP.NET Core itself resolves the environment from.
    /// </summary>
    private static bool IsProductionEnvironment()
    {
        var environment =
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
            ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

        // Unset means the ASP.NET Core default, which is Production.
        return string.IsNullOrWhiteSpace(environment)
            || string.Equals(environment, "Production", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsStandardClaim(string claimType) =>
        claimType is ClaimTypes.NameIdentifier or "sub"
            or ClaimTypes.Email or "email"
            or ClaimTypes.Name or "name"
            or ClaimTypes.GivenName or "given_name"
            or ClaimTypes.Surname or "family_name"
            or "picture" or "aud" or "iss" or "exp" or "nbf" or "iat";
}
