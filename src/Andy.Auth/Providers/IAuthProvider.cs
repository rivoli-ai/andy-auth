using Andy.Auth.Configuration;
using Andy.Auth.Models;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Andy.Auth.Providers;

/// <summary>
/// Abstraction for authentication providers (Andy Auth, Azure AD, Clerk, etc.)
/// </summary>
public interface IAuthProvider
{
    /// <summary>
    /// Provider name for identification
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Configure ASP.NET Core authentication for this provider
    /// </summary>
    /// <param name="builder">Authentication builder</param>
    /// <param name="options">Andy Auth configuration options</param>
    void ConfigureAuthentication(AuthenticationBuilder builder, AndyAuthOptions options);

    /// <summary>
    /// Extract standardized user claims from authenticated principal
    /// </summary>
    /// <param name="principal">Authenticated user principal</param>
    /// <returns>Standardized user claims</returns>
    Task<UserClaims> GetUserClaimsAsync(ClaimsPrincipal principal);

    /// <summary>
    /// Get OAuth metadata for MCP server discovery (RFC 8707)
    /// </summary>
    /// <returns>OAuth metadata</returns>
    OAuthMetadata GetOAuthMetadata(AndyAuthOptions options);
}
