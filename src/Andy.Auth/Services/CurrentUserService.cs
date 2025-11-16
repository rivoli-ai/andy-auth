using Andy.Auth.Models;
using Andy.Auth.Providers;
using Microsoft.AspNetCore.Http;

namespace Andy.Auth.Services;

/// <summary>
/// Default implementation of ICurrentUserService
/// </summary>
public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IAuthProvider _authProvider;

    public CurrentUserService(
        IHttpContextAccessor httpContextAccessor,
        IAuthProvider authProvider)
    {
        _httpContextAccessor = httpContextAccessor;
        _authProvider = authProvider;
    }

    public Task<string> GetUserIdAsync()
    {
        var principal = _httpContextAccessor.HttpContext?.User
            ?? throw new InvalidOperationException("HttpContext is not available");

        if (!principal.Identity?.IsAuthenticated ?? true)
            throw new InvalidOperationException("User is not authenticated");

        var claims = _authProvider.GetUserClaimsAsync(principal).GetAwaiter().GetResult();
        return Task.FromResult(claims.UserId);
    }

    public async Task<UserClaims> GetUserClaimsAsync()
    {
        var principal = _httpContextAccessor.HttpContext?.User
            ?? throw new InvalidOperationException("HttpContext is not available");

        if (!principal.Identity?.IsAuthenticated ?? true)
            throw new InvalidOperationException("User is not authenticated");

        return await _authProvider.GetUserClaimsAsync(principal);
    }

    public bool IsAuthenticated()
    {
        return _httpContextAccessor.HttpContext?.User?.Identity?.IsAuthenticated ?? false;
    }
}
