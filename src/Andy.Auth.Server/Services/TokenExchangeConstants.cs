namespace Andy.Auth.Server.Services;

/// <summary>
/// Constants for the RFC 8693 OAuth 2.0 Token Exchange grant. The URN
/// values are normative — they appear on the wire as <c>grant_type</c>
/// and <c>*_token_type</c> form parameters and as <c>typ</c> values in
/// audit logs. Defined once here so the registration in
/// <c>Program.cs</c> and the handler in <c>AuthorizationController</c>
/// cannot drift.
///
/// Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
internal static class TokenExchangeConstants
{
    /// <summary>
    /// <c>grant_type</c> URN per RFC 8693 §2.1.
    /// </summary>
    public const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>
    /// <c>token_type</c> URN identifying an OAuth 2.0 access token
    /// (RFC 8693 §3). The only subject-token type we accept on input
    /// — opaque tokens or SAML assertions are rejected.
    /// </summary>
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>
    /// Issued-token-type echoed in the token-exchange response per RFC
    /// 8693 §2.2.1 (<c>issued_token_type</c>). Always
    /// <c>access_token</c> for us — we don't mint refresh tokens for
    /// the exchanged grant.
    /// </summary>
    public const string IssuedTokenType = AccessTokenType;
}
