using Andy.Auth.Configuration;
using Andy.Auth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace Andy.Auth.Providers;

/// <summary>
/// Authentication provider for Clerk (supports both JWT and opaque tokens)
/// </summary>
public class ClerkProvider : IAuthProvider
{
    public string Name => "Clerk";

    public void ConfigureAuthentication(AuthenticationBuilder builder, AndyAuthOptions options)
    {
        if (options.Clerk == null || string.IsNullOrEmpty(options.Clerk.Domain))
            throw new ArgumentException("Clerk configuration with Domain is required for Clerk provider");

        var clerkDomain = options.Clerk.Domain;

        // Add policy scheme that routes to appropriate handler based on token type
        builder.AddPolicyScheme("ClerkSmartAuth", "Clerk Smart Authentication", policyOptions =>
        {
            policyOptions.ForwardDefaultSelector = context =>
            {
                var authHeader = context.Request.Headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    var token = authHeader.Substring("Bearer ".Length).Trim();
                    // If it's an opaque token (starts with oat_), use custom handler
                    if (token.StartsWith("oat_"))
                    {
                        return "ClerkOpaqueToken";
                    }
                }
                // Default to JWT Bearer for JWT tokens
                return JwtBearerDefaults.AuthenticationScheme;
            };
        });

        // JWT Bearer handler for standard JWT tokens
        builder.AddJwtBearer(options.AuthenticationScheme, jwtOptions =>
        {
            jwtOptions.Authority = $"https://{clerkDomain}";
            jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = $"https://{clerkDomain}",
                ValidateAudience = !string.IsNullOrEmpty(options.Clerk.Audience),
                ValidAudience = options.Clerk.Audience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                NameClaimType = ClaimTypes.NameIdentifier,
                RoleClaimType = ClaimTypes.Role
            };

            if (options.Events != null)
            {
                jwtOptions.Events = options.Events;
            }
        });

        // Custom handler for Clerk's opaque OAuth access tokens
        builder.AddScheme<ClerkOpaqueTokenOptions, ClerkOpaqueTokenHandler>("ClerkOpaqueToken", opaqueOptions =>
        {
            opaqueOptions.ClerkDomain = clerkDomain;
        });
    }

    public Task<UserClaims> GetUserClaimsAsync(ClaimsPrincipal principal)
    {
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                  ?? principal.FindFirst("sub")?.Value
                  ?? throw new InvalidOperationException("User ID claim not found in Clerk token");

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
        if (options.Clerk == null || string.IsNullOrEmpty(options.Clerk.Domain))
            throw new ArgumentException("Clerk configuration with Domain is required");

        var authority = new Uri($"https://{options.Clerk.Domain}");

        return new OAuthMetadata
        {
            AuthorizationServer = authority,
            AuthorizationEndpoint = new Uri(authority, "authorize"),
            TokenEndpoint = new Uri(authority, "token"),
            RegistrationEndpoint = null, // Clerk doesn't support DCR
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

/// <summary>
/// Options for Clerk opaque token handler
/// </summary>
public class ClerkOpaqueTokenOptions : Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions
{
    public string ClerkDomain { get; set; } = string.Empty;
}

/// <summary>
/// Custom authentication handler for Clerk's opaque OAuth access tokens (oat_*)
/// </summary>
public class ClerkOpaqueTokenHandler : Microsoft.AspNetCore.Authentication.AuthenticationHandler<ClerkOpaqueTokenOptions>
{
    private readonly IHttpClientFactory _httpClientFactory;

    public ClerkOpaqueTokenHandler(
        Microsoft.Extensions.Options.IOptionsMonitor<ClerkOpaqueTokenOptions> options,
        Microsoft.Extensions.Logging.ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder,
        IHttpClientFactory httpClientFactory)
        : base(options, logger, encoder)
    {
        _httpClientFactory = httpClientFactory;
    }

    protected override async Task<Microsoft.AspNetCore.Authentication.AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
            return Microsoft.AspNetCore.Authentication.AuthenticateResult.NoResult();

        string? authHeader = Request.Headers.Authorization;
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Microsoft.AspNetCore.Authentication.AuthenticateResult.NoResult();

        var token = authHeader.Substring("Bearer ".Length).Trim();

        // Only handle Clerk's opaque access tokens (start with "oat_")
        if (!token.StartsWith("oat_"))
            return Microsoft.AspNetCore.Authentication.AuthenticateResult.NoResult();

        try
        {
            // Validate token by calling Clerk's userinfo endpoint
            var httpClient = _httpClientFactory.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Get, $"https://{Options.ClerkDomain}/oauth/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
                return Microsoft.AspNetCore.Authentication.AuthenticateResult.Fail($"Invalid token: userinfo returned {response.StatusCode}");

            var userInfoJson = await response.Content.ReadAsStringAsync();
            var userInfo = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(userInfoJson);

            if (userInfo == null)
                return Microsoft.AspNetCore.Authentication.AuthenticateResult.Fail("Failed to parse userinfo response");

            // Extract claims
            var claims = new List<Claim>();

            if (userInfo.TryGetValue("sub", out var sub))
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, sub.GetString() ?? string.Empty));
                claims.Add(new Claim("sub", sub.GetString() ?? string.Empty));
            }
            else
            {
                return Microsoft.AspNetCore.Authentication.AuthenticateResult.Fail("Userinfo missing 'sub' claim");
            }

            if (userInfo.TryGetValue("email", out var email))
            {
                claims.Add(new Claim(ClaimTypes.Email, email.GetString() ?? string.Empty));
                claims.Add(new Claim("email", email.GetString() ?? string.Empty));
            }

            if (userInfo.TryGetValue("name", out var name))
            {
                claims.Add(new Claim(ClaimTypes.Name, name.GetString() ?? string.Empty));
                claims.Add(new Claim("name", name.GetString() ?? string.Empty));
            }

            if (userInfo.TryGetValue("picture", out var picture))
            {
                claims.Add(new Claim("picture", picture.GetString() ?? string.Empty));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new Microsoft.AspNetCore.Authentication.AuthenticationTicket(principal, Scheme.Name);

            return Microsoft.AspNetCore.Authentication.AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            return Microsoft.AspNetCore.Authentication.AuthenticateResult.Fail($"Error validating token: {ex.Message}");
        }
    }
}
