namespace Andy.Auth.Server.Models.Dcr;

/// <summary>
/// Credential-free before/after snapshot presented to an administrator when a
/// DCR update invalidates the client's prior approval.
/// </summary>
public sealed class DcrMetadataChangeReview
{
    public DateTime ChangedAt { get; init; }
    public List<string> PreviousRedirectUris { get; init; } = new();
    public List<string> ProposedRedirectUris { get; init; } = new();
    public List<string> PreviousPostLogoutRedirectUris { get; init; } = new();
    public List<string> ProposedPostLogoutRedirectUris { get; init; } = new();
}
