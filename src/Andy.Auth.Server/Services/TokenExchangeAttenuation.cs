namespace Andy.Auth.Server.Services;

/// <summary>
/// Pure RFC 8693 authority attenuation rules shared by the endpoint and its
/// negative tests. Every dimension is an intersection or minimum; none can
/// increase the authority carried by the subject token.
/// </summary>
public static class TokenExchangeAttenuation
{
    public static bool HasTrustedAudience(
        IEnumerable<string> subjectAudiences,
        IEnumerable<string> trustedAudiences)
    {
        var trusted = trustedAudiences.ToHashSet(StringComparer.Ordinal);
        return trusted.Count > 0 && subjectAudiences.Any(trusted.Contains);
    }

    public static ScopeAttenuationResult AttenuateScopes(
        IEnumerable<string> subjectScopes,
        IEnumerable<string> policyScopes,
        IEnumerable<string> requestedScopes)
    {
        var subject = subjectScopes.ToHashSet(StringComparer.Ordinal);
        var policy = policyScopes.ToHashSet(StringComparer.Ordinal);
        var maximum = subject
            .Where(scope => policy.Count == 0 || policy.Contains(scope))
            .ToHashSet(StringComparer.Ordinal);
        var requested = requestedScopes.ToList();
        var effective = requested.Count > 0 ? requested : maximum.ToList();
        var disallowed = effective
            .Where(scope => !maximum.Contains(scope))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        return new ScopeAttenuationResult(
            disallowed.Count == 0,
            effective,
            disallowed);
    }

    public static TimeSpan? CapLifetime(
        DateTimeOffset? subjectExpiresAt,
        DateTimeOffset now,
        TimeSpan configuredMaximum)
    {
        if (subjectExpiresAt is null || configuredMaximum <= TimeSpan.Zero)
        {
            return null;
        }

        var remaining = subjectExpiresAt.Value - now;
        if (remaining <= TimeSpan.Zero)
        {
            return null;
        }

        return remaining < configuredMaximum ? remaining : configuredMaximum;
    }
}

public sealed record ScopeAttenuationResult(
    bool IsAllowed,
    IReadOnlyList<string> EffectiveScopes,
    IReadOnlyList<string> DisallowedScopes);
