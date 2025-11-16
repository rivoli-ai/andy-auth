using Andy.Auth.Models;

namespace Andy.Auth.Services;

/// <summary>
/// Service for accessing the current authenticated user
/// </summary>
public interface ICurrentUserService
{
    /// <summary>
    /// Get the current user's ID from the authentication token
    /// </summary>
    /// <returns>User ID</returns>
    /// <exception cref="InvalidOperationException">Thrown when user is not authenticated</exception>
    Task<string> GetUserIdAsync();

    /// <summary>
    /// Get all user claims from the current authenticated user
    /// </summary>
    /// <returns>Standardized user claims</returns>
    /// <exception cref="InvalidOperationException">Thrown when user is not authenticated</exception>
    Task<UserClaims> GetUserClaimsAsync();

    /// <summary>
    /// Check if a user is currently authenticated
    /// </summary>
    /// <returns>True if authenticated, false otherwise</returns>
    bool IsAuthenticated();
}
