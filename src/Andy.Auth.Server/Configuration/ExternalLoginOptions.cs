namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Policy governing external (federated) sign-in and account linking.
///
/// These settings make the trust requirements for an external identity
/// EXPLICIT. See <c>docs/SECURITY.md</c> ("External Login &amp; Account
/// Linking") for the security rationale and the invariant that an external
/// identity is never auto-linked to an existing local account by email alone.
/// </summary>
public class ExternalLoginOptions
{
    /// <summary>
    /// Section name in appsettings.json.
    /// </summary>
    public const string SectionName = "ExternalLogin";

    /// <summary>
    /// When true (the default), the external provider must assert a verified
    /// email (an <c>email_verified</c>/<c>verified_email</c> claim equal to
    /// <c>true</c>) before a new account is provisioned or an existing account
    /// is linked. Providers that do not emit the claim must be configured to
    /// map it, or an operator must explicitly opt out by setting this to false.
    /// </summary>
    public bool RequireVerifiedEmail { get; set; } = true;

    /// <summary>
    /// Allowed provider tenant IDs (the Azure/Entra <c>tid</c> claim). When
    /// non-empty (and not the wildcard "common"), the external principal's
    /// tenant must appear in this list or sign-in/linking is rejected. Empty
    /// means "any tenant".
    /// </summary>
    public List<string> AllowedTenantIds { get; set; } = new();

    /// <summary>
    /// Allowed token issuers (the <c>iss</c> claim). When non-empty, the
    /// external principal's issuer must appear in this list or sign-in/linking
    /// is rejected. Empty means "any issuer".
    /// </summary>
    public List<string> AllowedIssuers { get; set; } = new();

    /// <summary>
    /// Whether an already-linked external sign-in may bypass a locally
    /// configured second factor. Defaults to <c>false</c>: local 2FA is
    /// ENFORCED even after a successful external sign-in. Set to true only when
    /// upstream MFA is trusted to satisfy the local second-factor requirement.
    /// </summary>
    public bool BypassLocalTwoFactor { get; set; }
}
