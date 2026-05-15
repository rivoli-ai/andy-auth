using Andy.Auth.Server.Configuration;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Evaluates the RFC 8693 token-exchange allow-list defined in
/// <see cref="TokenExchangeSettings"/>. See the class doc on
/// <see cref="TokenExchangeSettings"/> for the wider context.
/// </summary>
public interface ITokenExchangePolicy
{
    /// <summary>
    /// Returns true if <paramref name="actorClientId"/> may act on
    /// behalf of a user for <paramref name="audience"/>. Both the
    /// master switch and the (actor, audience) pair must allow.
    /// </summary>
    bool IsAllowed(string actorClientId, string audience);

    /// <summary>
    /// Returns the scopes the actor is allowed to request on the
    /// exchanged token for this (actor, audience) pair. When the
    /// policy entry has no explicit allow-list, returns an empty
    /// collection — the caller should treat that as "pass the
    /// subject token's scopes through unchanged" per the policy
    /// definition.
    /// </summary>
    IReadOnlyList<string> AllowedScopes(string actorClientId, string audience);
}

/// <summary>
/// Default <see cref="ITokenExchangePolicy"/> implementation backed by
/// <see cref="TokenExchangeSettings"/> (which is bound from
/// <c>appsettings.json</c>'s <c>TokenExchange</c> section).
///
/// Registered as a singleton: the policy is static for the process
/// lifetime. A future story will swap this for a DB-backed policy that
/// can be edited at runtime through the admin UI; the interface here
/// is deliberately shaped so the swap is mechanical.
/// </summary>
public class TokenExchangePolicy : ITokenExchangePolicy
{
    private readonly TokenExchangeSettings _settings;

    public TokenExchangePolicy(IOptions<TokenExchangeSettings> settings)
    {
        _settings = settings.Value;
    }

    public bool IsAllowed(string actorClientId, string audience)
    {
        if (!_settings.Enabled)
        {
            return false;
        }
        if (string.IsNullOrWhiteSpace(actorClientId) || string.IsNullOrWhiteSpace(audience))
        {
            return false;
        }
        return _settings.Policies.Any(p =>
            string.Equals(p.ActorClientId, actorClientId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(p.Audience, audience, StringComparison.Ordinal));
    }

    public IReadOnlyList<string> AllowedScopes(string actorClientId, string audience)
    {
        var entry = _settings.Policies.FirstOrDefault(p =>
            string.Equals(p.ActorClientId, actorClientId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(p.Audience, audience, StringComparison.Ordinal));
        return entry?.AllowedScopes ?? new List<string>();
    }
}
