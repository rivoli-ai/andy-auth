namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Configuration for the RFC 8693 OAuth 2.0 Token Exchange grant
/// (<c>urn:ietf:params:oauth:grant-type:token-exchange</c>).
///
/// Token exchange is the platform's primitive for cross-service
/// identity propagation: when service A (the <em>actor</em>) receives a
/// user request and needs to call service B (the <em>resource</em>), it
/// presents the user's access token as <c>subject_token</c> and its own
/// client credentials as the actor. andy-auth issues a new token whose
/// <c>sub</c> claim is the user, whose <c>act</c> claim is the actor,
/// and whose <c>aud</c> claim is the requested downstream audience.
///
/// The policy below gates which actor client_ids may act on behalf of
/// users for which audiences. This is an allow-list — anything not
/// listed is denied. Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
public class TokenExchangeSettings
{
    /// <summary>
    /// Section name in <c>appsettings.json</c>.
    /// </summary>
    public const string SectionName = "TokenExchange";

    /// <summary>
    /// Master switch. When false, the token-exchange grant is rejected
    /// regardless of policy. Defaults to true so the bundled deployment
    /// has the feature available out of the box; deployments that want
    /// to disable it can set <c>TokenExchange:Enabled = false</c>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Allow-list of (actor, audience) pairs. An actor is identified by
    /// its OpenIddict <c>client_id</c>; the audience matches the
    /// <c>aud</c> claim of the issued token (e.g. <c>urn:andy-models-api</c>).
    ///
    /// An empty list means token exchange is effectively disabled — any
    /// well-formed request will fail the policy check.
    /// </summary>
    public List<TokenExchangePolicyEntry> Policies { get; set; } = new();

    /// <summary>
    /// Lifetime of exchanged access tokens. Should be short enough to
    /// limit confused-deputy blast radius and long enough that
    /// downstream callers don't re-exchange on every request. 15
    /// minutes is the default; tune per deployment.
    /// </summary>
    public TimeSpan ExchangedTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// A single entry in the token-exchange allow-list.
/// </summary>
public class TokenExchangePolicyEntry
{
    /// <summary>
    /// OpenIddict <c>client_id</c> of the calling service. Matched
    /// case-insensitively against the authenticated client on the
    /// <c>/connect/token</c> request.
    /// </summary>
    public string ActorClientId { get; set; } = string.Empty;

    /// <summary>
    /// Requested audience on the exchanged token (the downstream
    /// service the actor wants to call), e.g. <c>urn:andy-models-api</c>.
    /// Matched case-sensitively because audiences are URNs.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Optional allow-list of scopes the actor may request on the
    /// exchanged token. If empty, the original subject token's scopes
    /// pass through unchanged. If non-empty, requested scopes must be
    /// a subset of this list.
    /// </summary>
    public List<string> AllowedScopes { get; set; } = new();
}
