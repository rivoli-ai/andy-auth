using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Represents a user's consent grant to an OAuth client application.
/// Tracks what scopes a user has approved for a specific client.
/// </summary>
public class UserConsent
{
    /// <summary>
    /// Unique identifier for the consent record.
    /// </summary>
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// The user who granted consent.
    /// </summary>
    [Required]
    [MaxLength(450)]
    public string UserId { get; set; } = null!;

    /// <summary>
    /// Navigation property to the user.
    /// </summary>
    [ForeignKey(nameof(UserId))]
    public ApplicationUser? User { get; set; }

    /// <summary>
    /// The OAuth client ID that received consent.
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string ClientId { get; set; } = null!;

    /// <summary>
    /// The scopes that were granted, stored as space-separated values.
    /// </summary>
    [Required]
    public string Scopes { get; set; } = null!;

    /// <summary>
    /// When the consent was granted.
    /// </summary>
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Optional expiration date for the consent.
    /// If null, consent does not expire.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Whether the user chose to remember this consent decision.
    /// </summary>
    public bool RememberConsent { get; set; } = true;

    /// <summary>
    /// Gets the scopes as a list.
    /// </summary>
    [NotMapped]
    public IEnumerable<string> ScopesList =>
        string.IsNullOrEmpty(Scopes)
            ? Enumerable.Empty<string>()
            : Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// Sets the scopes from a list.
    /// </summary>
    public void SetScopes(IEnumerable<string> scopes)
    {
        Scopes = string.Join(" ", scopes);
    }

    /// <summary>
    /// Checks if this consent covers all the requested scopes.
    /// </summary>
    public bool CoversScopes(IEnumerable<string> requestedScopes)
    {
        var grantedScopes = ScopesList.ToHashSet();
        return requestedScopes.All(s => grantedScopes.Contains(s));
    }

    /// <summary>
    /// Checks if the consent is still valid (not expired).
    /// </summary>
    public bool IsValid => ExpiresAt == null || ExpiresAt > DateTime.UtcNow;
}
