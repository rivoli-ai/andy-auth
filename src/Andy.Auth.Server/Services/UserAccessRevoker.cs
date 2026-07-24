using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Tears down every credential a user currently holds. Invoked whenever an
/// admin surface disables an account (suspend, expire, deactivate, soft
/// delete).
/// </summary>
/// <remarks>
/// andy-auth#146. Blocking future sign-ins via <see cref="UserLifecycle"/> is
/// only half the fix: without this, credentials issued *before* the admin
/// action stay live. Specifically —
/// <list type="bullet">
/// <item>the Identity auth cookie survives until it expires, so the user keeps
/// a browser session (the security stamp bump closes it at the next
/// validation interval);</item>
/// <item>refresh tokens keep minting access tokens, because the OpenIddict
/// authorization backing them is still <c>valid</c>;</item>
/// <item>already-minted access tokens are unencrypted JWTs validated offline
/// and cannot be recalled at all — they simply have to expire. That residual
/// window is the reason access-token lifetime matters here.</item>
/// </list>
/// </remarks>
public interface IUserAccessRevoker
{
    /// <inheritdoc cref="UserAccessRevoker.RevokeAllAccessAsync"/>
    Task RevokeAllAccessAsync(ApplicationUser user, string reason);
}

/// <inheritdoc cref="IUserAccessRevoker"/>
public class UserAccessRevoker : IUserAccessRevoker
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly SessionService _sessionService;
    private readonly ILogger<UserAccessRevoker> _logger;

    public UserAccessRevoker(
        UserManager<ApplicationUser> userManager,
        IOpenIddictTokenManager tokenManager,
        IOpenIddictAuthorizationManager authorizationManager,
        SessionService sessionService,
        ILogger<UserAccessRevoker> logger)
    {
        _userManager = userManager;
        _tokenManager = tokenManager;
        _authorizationManager = authorizationManager;
        _sessionService = sessionService;
        _logger = logger;
    }

    /// <summary>
    /// Revokes the user's OpenIddict tokens and authorizations, closes their
    /// tracked sessions, and rotates their security stamp.
    /// </summary>
    /// <remarks>
    /// Best-effort per step: a failure revoking one token must not leave the
    /// remaining ones live, so each step is isolated and logged rather than
    /// allowed to abort the sweep. The caller has already persisted the
    /// lifecycle flag, which is what actually blocks re-authentication.
    /// </remarks>
    public async Task RevokeAllAccessAsync(ApplicationUser user, string reason)
    {
        var tokensRevoked = 0;
        try
        {
            await foreach (var token in _tokenManager.FindBySubjectAsync(user.Id))
            {
                if (await _tokenManager.TryRevokeAsync(token))
                {
                    tokensRevoked++;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke tokens for user {UserId}", user.Id);
        }

        var authorizationsRevoked = 0;
        try
        {
            await foreach (var authorization in _authorizationManager.FindBySubjectAsync(user.Id))
            {
                if (await _authorizationManager.TryRevokeAsync(authorization))
                {
                    authorizationsRevoked++;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke authorizations for user {UserId}", user.Id);
        }

        var sessionsRevoked = 0;
        try
        {
            sessionsRevoked = await _sessionService.RevokeAllSessionsAsync(user.Id, reason);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke sessions for user {UserId}", user.Id);
        }

        try
        {
            // Invalidates the Identity auth cookie at the next security-stamp
            // validation interval, so an open browser tab loses its session.
            await _userManager.UpdateSecurityStampAsync(user);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to rotate security stamp for user {UserId}", user.Id);
        }

        _logger.LogInformation(
            "Revoked access for user {UserId} ({Reason}): {Tokens} tokens, {Authorizations} authorizations, {Sessions} sessions",
            user.Id, reason, tokensRevoked, authorizationsRevoked, sessionsRevoked);
    }
}
