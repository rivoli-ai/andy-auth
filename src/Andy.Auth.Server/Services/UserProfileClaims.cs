using Andy.Auth.Server.Data;

namespace Andy.Auth.Server.Services;

/// <summary>Applies the same email-scope boundary to tokens and userinfo.</summary>
public static class UserProfileClaims
{
    public static string DisplayName(ApplicationUser user, bool includeEmail) =>
        new[] { user.FullName, user.UserName }.FirstOrDefault(value =>
            IsAllowed(value, user.Email, includeEmail)) ?? user.Id;

    public static string? PreferredUsername(ApplicationUser user, bool includeEmail) =>
        IsAllowed(user.UserName, user.Email, includeEmail) ? user.UserName : null;

    private static bool IsAllowed(string? value, string? email, bool includeEmail) =>
        !string.IsNullOrWhiteSpace(value) &&
        (includeEmail || !string.Equals(value, email, StringComparison.OrdinalIgnoreCase));
}
