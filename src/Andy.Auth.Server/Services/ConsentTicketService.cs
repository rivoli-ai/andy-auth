using Microsoft.AspNetCore.DataProtection;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Mints and verifies the short-lived proof that a user just approved an
/// authorization request on the consent screen.
/// </summary>
/// <remarks>
/// <para>
/// andy-auth#124. The consent screen used to signal approval by appending
/// <c>consent_granted=true</c> to the return URL, and
/// <c>AuthorizationController.Authorize</c> treated that query parameter as
/// proof. The whole authorization request is client-controlled, so anyone
/// could append it themselves — or send a victim a link with it already
/// present — and the consent screen never appeared. No <c>UserConsent</c> row
/// was written either, so nothing downstream recorded that consent had
/// (supposedly) been given.
/// </para>
/// <para>
/// A ticket is an authenticated, time-limited payload produced by ASP.NET
/// Core Data Protection. It binds the approval to the user who gave it, the
/// client it was given to, the redirect URI in play, and the exact scope
/// subset that was ticked — so a ticket cannot be forged, replayed against a
/// different client, or widened to scopes the user did not approve.
/// </para>
/// </remarks>
public class ConsentTicketService
{
    /// <summary>
    /// How long a ticket stays usable. Only has to cover the redirect from
    /// the consent POST back to <c>/connect/authorize</c>, so it is deliberately
    /// far shorter than any consent record it may accompany.
    /// </summary>
    public static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Query-string parameter carrying the ticket.</summary>
    public const string QueryParameterName = "consent_token";

    private const string Purpose = "Andy.Auth.Server.ConsentTicket.v1";
    private const char FieldSeparator = '';   // unit separator: cannot occur in any field

    private readonly ITimeLimitedDataProtector _protector;
    private readonly ILogger<ConsentTicketService> _logger;

    public ConsentTicketService(
        IDataProtectionProvider dataProtectionProvider,
        ILogger<ConsentTicketService> logger)
    {
        _protector = dataProtectionProvider.CreateProtector(Purpose).ToTimeLimitedDataProtector();
        _logger = logger;
    }

    /// <summary>
    /// Issues a ticket recording that <paramref name="userId"/> approved
    /// <paramref name="approvedScopes"/> for <paramref name="clientId"/>.
    /// </summary>
    public string Issue(
        string userId,
        string clientId,
        string? redirectUri,
        IEnumerable<string> approvedScopes)
    {
        var payload = string.Join(FieldSeparator, new[]
        {
            userId,
            clientId,
            redirectUri ?? string.Empty,
            string.Join(' ', approvedScopes.OrderBy(s => s, StringComparer.Ordinal)),
        });

        return _protector.Protect(payload, TicketLifetime);
    }

    /// <summary>
    /// Validates a ticket against the request it is being presented for.
    /// Returns the approved scopes, or null if the ticket is absent, forged,
    /// expired, or bound to a different user/client/redirect URI.
    /// </summary>
    public IReadOnlyList<string>? Redeem(
        string? ticket,
        string userId,
        string? clientId,
        string? redirectUri)
    {
        if (string.IsNullOrEmpty(ticket))
        {
            return null;
        }

        string payload;
        try
        {
            payload = _protector.Unprotect(ticket);
        }
        catch (Exception ex)
        {
            // Tampered, expired, or minted under a rotated key. All are
            // "no consent" — never a hint to the caller about which.
            _logger.LogWarning(ex, "Consent ticket rejected");
            return null;
        }

        var fields = payload.Split(FieldSeparator);
        if (fields.Length != 4)
        {
            _logger.LogWarning("Consent ticket rejected: malformed payload");
            return null;
        }

        // Every binding must match the request actually being authorized.
        // Without the client check a ticket approved for a benign client would
        // authorize a hostile one; without the redirect check it would
        // authorize delivery of the code somewhere else.
        if (!string.Equals(fields[0], userId, StringComparison.Ordinal) ||
            !string.Equals(fields[1], clientId ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(fields[2], redirectUri ?? string.Empty, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "Consent ticket rejected: bound to a different user, client or redirect_uri");
            return null;
        }

        return fields[3].Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }
}
