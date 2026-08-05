using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Validates the <c>subject_token</c> parameter of an RFC 8693 token
/// exchange request. The subject token must be a valid access token
/// issued by this same andy-auth server — the policy is that only
/// tokens minted here can be exchanged here.
///
/// Validation uses the same signing + encryption keys configured on
/// <see cref="OpenIddictServerOptions"/>, so any token the server has
/// just issued through the normal authorization-code / refresh-token
/// flows is accepted. Audience authorization is performed by the exchange
/// policy because the trusted source audience depends on the authenticated
/// actor/target pair, but the validator returns the verified audience values.
///
/// Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
public interface ISubjectTokenValidator
{
    Task<SubjectTokenValidationResult> ValidateAsync(string subjectToken, CancellationToken ct = default);
}

/// <summary>
/// Outcome of <see cref="ISubjectTokenValidator.ValidateAsync"/>.
/// <c>IsValid</c> + <c>Subject</c> on success; <c>FailureReason</c> on
/// failure (a single sentence safe to log; not safe to surface to the
/// caller verbatim — see RFC 8693 §2.2.2).
/// </summary>
public record SubjectTokenValidationResult(
    bool IsValid,
    string? Subject,
    IReadOnlyList<string> Scopes,
    string? FailureReason,
    IReadOnlyList<string>? Audiences = null,
    DateTimeOffset? ExpiresAt = null,
    string? SessionId = null);

public class InProcessSubjectTokenValidator : ISubjectTokenValidator
{
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly ILogger<InProcessSubjectTokenValidator> _logger;

    public InProcessSubjectTokenValidator(
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        ILogger<InProcessSubjectTokenValidator> logger)
    {
        _serverOptions = serverOptions;
        _logger = logger;
    }

    public async Task<SubjectTokenValidationResult> ValidateAsync(string subjectToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectToken))
        {
            return new SubjectTokenValidationResult(false, null, Array.Empty<string>(), "subject_token is missing");
        }

        var options = _serverOptions.CurrentValue;
        if (options.Issuer is null)
        {
            return new SubjectTokenValidationResult(false, null, Array.Empty<string>(), "issuer not configured");
        }

        var signingKeys = options.SigningCredentials
            .Select(c => c.Key)
            .OfType<SecurityKey>()
            .ToList();
        var decryptionKeys = options.EncryptionCredentials
            .Select(c => c.Key)
            .OfType<SecurityKey>()
            .ToList();

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            // Accept the issuer both with and without a trailing slash. OpenIddict
            // issues the `iss` claim verbatim from the configured issuer URI, which
            // carries a trailing slash (e.g. "http://localhost:9100/auth/"), while a
            // single trimmed ValidIssuer ("…/auth") is an exact-match miss → the
            // subject_token is rejected and the whole OBO exchange fails with
            // invalid_grant (rivoli-ai/conductor#1973). List both normalized forms.
            ValidIssuers = new[]
            {
                options.Issuer.ToString(),
                options.Issuer.ToString().TrimEnd('/'),
            },
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            // OpenIddict access tokens use the RFC 9068 media type. This
            // rejects ID tokens (JWT) and unrelated locally signed JWTs even
            // when they share this server's signing key (#170).
            ValidTypes = new[] { "at+jwt" },
            IssuerSigningKeys = signingKeys,
            TokenDecryptionKeys = decryptionKeys.Count > 0 ? decryptionKeys : null,
            NameClaimType = "sub",
        };

        var handler = new JsonWebTokenHandler();
        TokenValidationResult result;
        try
        {
            result = await handler.ValidateTokenAsync(subjectToken, validationParameters);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "subject_token validation threw");
            return new SubjectTokenValidationResult(false, null, Array.Empty<string>(),
                "subject_token validation failed");
        }

        if (!result.IsValid)
        {
            // Surface the concrete reason (IDX10223 expired, IDX10205 issuer,
            // signature, etc.) in the returned FailureReason — the token-exchange
            // handler logs it at Warning, so operators can tell an expired user
            // token from a real config problem without a debug build
            // (conductor#1973). The token itself is never logged.
            var detail = result.Exception?.Message ?? "unknown validation failure";
            _logger.LogWarning(result.Exception, "subject_token rejected: {Reason}", detail);
            return new SubjectTokenValidationResult(false, null, Array.Empty<string>(),
                $"subject_token rejected: {detail}");
        }

        var sub = result.ClaimsIdentity?.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub) && result.Claims.TryGetValue("sub", out var subClaim))
        {
            sub = subClaim?.ToString();
        }
        if (string.IsNullOrWhiteSpace(sub))
        {
            return new SubjectTokenValidationResult(false, null, Array.Empty<string>(),
                "subject_token has no sub claim");
        }

        // Scopes in OpenIddict are stored as `oi_scp` (private claim) for
        // access tokens. Fall back to standard `scope`/`scp` for tokens
        // minted with the public claim form.
        var scopes = ExtractScopes(result);
        var audiences = result.SecurityToken is JsonWebToken jwt
            ? jwt.Audiences.ToArray()
            : Array.Empty<string>();
        var expiresAt = result.SecurityToken is JsonWebToken expiringJwt &&
                        expiringJwt.ValidTo != DateTime.MinValue
            ? new DateTimeOffset(DateTime.SpecifyKind(expiringJwt.ValidTo, DateTimeKind.Utc))
            : (DateTimeOffset?)null;
        var sessionId = result.ClaimsIdentity?.FindFirst(
            AndyAuthSignInManager.SessionIdClaimType)?.Value;

        return new SubjectTokenValidationResult(
            true, sub, scopes, null, audiences, expiresAt, sessionId);
    }

    private static IReadOnlyList<string> ExtractScopes(TokenValidationResult result)
    {
        if (result.Claims.TryGetValue("oi_scp", out var oiScp) && oiScp is not null)
        {
            return SplitScopeValue(oiScp);
        }
        if (result.Claims.TryGetValue("scope", out var scope) && scope is not null)
        {
            return SplitScopeValue(scope);
        }
        if (result.Claims.TryGetValue("scp", out var scp) && scp is not null)
        {
            return SplitScopeValue(scp);
        }
        return Array.Empty<string>();
    }

    private static IReadOnlyList<string> SplitScopeValue(object value)
    {
        // OpenIddict serializes multi-value claims as JSON arrays in
        // claims dictionaries, but as space-delimited strings on the
        // wire. Tolerate both.
        switch (value)
        {
            case string s when !string.IsNullOrWhiteSpace(s):
                return s.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            case System.Collections.IEnumerable e:
                return e.Cast<object?>()
                    .Where(x => x is not null)
                    .Select(x => x!.ToString()!)
                    .ToArray();
            default:
                return Array.Empty<string>();
        }
    }
}
