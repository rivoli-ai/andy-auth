using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Short-lived, single-use, server-side record of an interactive consent
/// approval. Created by <c>ConsentController</c> when the user clicks
/// "Allow" and consumed by <c>AuthorizationController</c> the moment the
/// browser is redirected back to the authorization endpoint.
///
/// This is the security-critical replacement for the previous
/// <c>consent_granted=true</c> query marker (issue #124). Because the marker
/// lived in the client-controlled authorization request, a client could
/// supply it itself and skip the consent screen. A <see cref="ConsentGrant"/>
/// instead binds the approval to the authenticated user, the client, the
/// redirect URI, the exact requested scope set, and the exact approved scope
/// subset, and expires quickly. The authorization endpoint only proceeds when
/// it can look up a matching, unconsumed, unexpired grant, and then issues
/// only <see cref="GrantedScopes"/> — never the raw requested scopes.
/// </summary>
public class ConsentGrant
{
    /// <summary>
    /// Surrogate primary key.
    /// </summary>
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// The unguessable, cryptographically random identifier handed back to the
    /// browser (as the <c>consent_id</c> query parameter) and used to look up
    /// this record at the authorization endpoint. This is the only part of the
    /// consent state that travels through the client.
    /// </summary>
    [Required]
    [MaxLength(128)]
    public string GrantId { get; set; } = null!;

    /// <summary>
    /// The authenticated user the approval is bound to.
    /// </summary>
    [Required]
    [MaxLength(450)]
    public string UserId { get; set; } = null!;

    /// <summary>
    /// The OAuth client the approval is bound to.
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string ClientId { get; set; } = null!;

    /// <summary>
    /// The redirect URI the approval is bound to. Stored exactly as parsed so
    /// the authorization endpoint can compare it against the redirect URI on
    /// the incoming request (tamper detection).
    /// </summary>
    [MaxLength(2000)]
    public string? RedirectUri { get; set; }

    /// <summary>
    /// The full set of scopes that were requested at consent time, stored as
    /// space-separated values. The authorization endpoint requires the
    /// incoming request's scope set to match this exactly, so a client cannot
    /// widen the scope set after the user has approved it.
    /// </summary>
    [Required]
    public string RequestedScopes { get; set; } = null!;

    /// <summary>
    /// The subset of scopes the user actually approved, stored as
    /// space-separated values. This — and only this — is what the
    /// authorization endpoint issues.
    /// </summary>
    [Required]
    public string GrantedScopes { get; set; } = null!;

    /// <summary>
    /// When the grant was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the grant expires. Consent grants are intentionally short-lived:
    /// they only need to survive the redirect from the consent screen back to
    /// the authorization endpoint.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// When the grant was consumed, or <c>null</c> if it has not been consumed
    /// yet. A grant may only be consumed once; a second attempt (replay) is
    /// rejected.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// The requested scopes as a set.
    /// </summary>
    [NotMapped]
    public IReadOnlyCollection<string> RequestedScopesList =>
        string.IsNullOrEmpty(RequestedScopes)
            ? Array.Empty<string>()
            : RequestedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// The approved scopes as a set.
    /// </summary>
    [NotMapped]
    public IReadOnlyCollection<string> GrantedScopesList =>
        string.IsNullOrEmpty(GrantedScopes)
            ? Array.Empty<string>()
            : GrantedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// Sets the requested scope set from a list.
    /// </summary>
    public void SetRequestedScopes(IEnumerable<string> scopes) =>
        RequestedScopes = string.Join(' ', scopes);

    /// <summary>
    /// Sets the approved scope set from a list.
    /// </summary>
    public void SetGrantedScopes(IEnumerable<string> scopes) =>
        GrantedScopes = string.Join(' ', scopes);
}
