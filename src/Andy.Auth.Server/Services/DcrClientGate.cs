using Andy.Auth.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Decides whether a dynamically-registered client may still be used, and why
/// not when it may not.
/// </summary>
/// <remarks>
/// One implementation shared by the authorization, token and device-verify
/// paths. It was previously a private helper copied into two controllers,
/// which is exactly the shape that let the claims-principal builders drift in
/// andy-auth#149.
/// </remarks>
public class DcrClientGate
{
    private readonly ApplicationDbContext _dbContext;

    public DcrClientGate(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    /// <summary>
    /// Returns null when the client may proceed, otherwise a caller-safe
    /// description of why it may not.
    /// </summary>
    public async Task<string?> GetDenialReasonAsync(string clientId)
    {
        var dcr = await _dbContext.DynamicClientRegistrations
            .AsNoTracking()
            .Where(d => d.ClientId == clientId)
            .Select(d => new { d.IsApproved, d.IsDisabled, d.ClientSecretExpiresAt })
            .FirstOrDefaultAsync();

        if (dcr == null)
        {
            // Fail closed on an orphan (andy-auth#120). A client_id carrying the
            // DCR-issued prefix but with no DynamicClientRegistration metadata is
            // an incomplete or partially-rolled-back registration — it must not
            // fall through to the permissive "not a DCR client" path and be
            // allowed to authorize or mint tokens. Genuine first-party clients
            // are seeded from manifests and never carry the prefix, so they keep
            // the permissive path.
            return DcrService.IsDcrIssuedClientId(clientId)
                ? "The client registration is incomplete."
                : null;
        }

        if (!dcr.IsApproved || dcr.IsDisabled)
        {
            return "The client application is disabled or pending approval.";
        }

        // RFC 7591 §3.2.1: client_secret_expires_at of 0 means the secret does
        // not expire. Anything else is a deadline we advertised in the
        // registration response and then never enforced — the secret outlived
        // its stated lifetime indefinitely (andy-auth#153).
        if (dcr.ClientSecretExpiresAt > 0 &&
            DateTimeOffset.FromUnixTimeSeconds(dcr.ClientSecretExpiresAt) <= DateTimeOffset.UtcNow)
        {
            return "The client secret has expired. Re-register or rotate the secret via RFC 7592.";
        }

        return null;
    }

    /// <summary>Convenience wrapper for callers that don't need the reason.</summary>
    public async Task<bool> IsActiveAsync(string clientId) =>
        await GetDenialReasonAsync(clientId) is null;
}
