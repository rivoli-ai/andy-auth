using System.Security.Claims;

namespace Andy.Auth.Tests.Helpers;

/// <summary>
/// Factory for creating test ClaimsPrincipal instances
/// </summary>
public static class TestClaimsPrincipalFactory
{
    public static ClaimsPrincipal CreateAndyAuthPrincipal(
        string userId = "test-user-123",
        string? email = "test@example.com",
        string? name = "Test User")
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new("sub", userId)
        };

        if (email != null)
        {
            claims.Add(new Claim(ClaimTypes.Email, email));
            claims.Add(new Claim("email", email));
        }

        if (name != null)
        {
            claims.Add(new Claim(ClaimTypes.Name, name));
            claims.Add(new Claim("name", name));
        }

        var identity = new ClaimsIdentity(claims, "TestAuth");
        return new ClaimsPrincipal(identity);
    }

    public static ClaimsPrincipal CreateAzureAdPrincipal(
        string objectId = "12345678-1234-1234-1234-123456789012",
        string? upn = "test@contoso.com",
        string? name = "Test User",
        string? tenantId = "87654321-4321-4321-4321-210987654321")
    {
        var claims = new List<Claim>
        {
            new("oid", objectId),
            new("sub", objectId)
        };

        if (upn != null)
        {
            claims.Add(new Claim("preferred_username", upn));
            claims.Add(new Claim("upn", upn));
        }

        if (name != null)
        {
            claims.Add(new Claim("name", name));
        }

        if (tenantId != null)
        {
            claims.Add(new Claim("tid", tenantId));
        }

        var identity = new ClaimsIdentity(claims, "TestAuth");
        return new ClaimsPrincipal(identity);
    }

    public static ClaimsPrincipal CreateClerkPrincipal(
        string userId = "user_2abcdef123456",
        string? email = "test@example.com",
        string? name = "Test User",
        string? picture = "https://example.com/avatar.jpg")
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new("sub", userId)
        };

        if (email != null)
        {
            claims.Add(new Claim(ClaimTypes.Email, email));
            claims.Add(new Claim("email", email));
        }

        if (name != null)
        {
            claims.Add(new Claim(ClaimTypes.Name, name));
            claims.Add(new Claim("name", name));
        }

        if (picture != null)
        {
            claims.Add(new Claim("picture", picture));
        }

        var identity = new ClaimsIdentity(claims, "TestAuth");
        return new ClaimsPrincipal(identity);
    }
}
