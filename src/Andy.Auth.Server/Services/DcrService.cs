using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models.Dcr;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Andy.Auth.Server.Services;

/// <summary>
/// Service for Dynamic Client Registration operations.
/// </summary>
public class DcrService
{
    private readonly ApplicationDbContext _context;
    private readonly DcrSettings _settings;
    private readonly ILogger<DcrService> _logger;

    public DcrService(
        ApplicationDbContext context,
        IOptions<DcrSettings> settings,
        ILogger<DcrService> logger)
    {
        _context = context;
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Validates the client registration request.
    /// </summary>
    public (bool IsValid, ClientRegistrationError? Error) ValidateRegistrationRequest(ClientRegistrationRequest request)
    {
        // Validate redirect URIs
        if (request.RedirectUris != null && request.RedirectUris.Count > 0)
        {
            if (request.RedirectUris.Count > _settings.MaxRedirectUrisPerClient)
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidClientMetadata,
                    ErrorDescription = $"Maximum {_settings.MaxRedirectUrisPerClient} redirect URIs allowed."
                });
            }

            foreach (var uri in request.RedirectUris)
            {
                var (valid, error) = ValidateRedirectUri(uri);
                if (!valid)
                {
                    return (false, error);
                }
            }
        }

        // Validate grant types
        if (request.GrantTypes != null)
        {
            foreach (var grantType in request.GrantTypes)
            {
                if (!_settings.AllowedGrantTypes.Contains(grantType))
                {
                    return (false, new ClientRegistrationError
                    {
                        Error = DcrErrorCodes.InvalidClientMetadata,
                        ErrorDescription = $"Grant type '{grantType}' is not allowed."
                    });
                }
            }

            // authorization_code requires redirect_uris
            if (request.GrantTypes.Contains("authorization_code") &&
                (request.RedirectUris == null || request.RedirectUris.Count == 0))
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidClientMetadata,
                    ErrorDescription = "redirect_uris is required for authorization_code grant type."
                });
            }
        }

        // Validate response types match grant types
        if (request.ResponseTypes != null && request.GrantTypes != null)
        {
            if (request.ResponseTypes.Contains("code") && !request.GrantTypes.Contains("authorization_code"))
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidClientMetadata,
                    ErrorDescription = "response_type 'code' requires grant_type 'authorization_code'."
                });
            }
        }

        // Validate application type
        if (request.ApplicationType != null)
        {
            var validTypes = new[] { "web", "native", "service" };
            if (!validTypes.Contains(request.ApplicationType.ToLowerInvariant()))
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidClientMetadata,
                    ErrorDescription = "application_type must be 'web', 'native', or 'service'."
                });
            }
        }

        // Validate token endpoint auth method
        if (request.TokenEndpointAuthMethod != null)
        {
            var validMethods = new[] { "client_secret_basic", "client_secret_post", "none" };
            if (!validMethods.Contains(request.TokenEndpointAuthMethod.ToLowerInvariant()))
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidClientMetadata,
                    ErrorDescription = "Invalid token_endpoint_auth_method."
                });
            }
        }

        // Validate client name length
        if (request.ClientName != null && request.ClientName.Length > _settings.MaxClientNameLength)
        {
            return (false, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = $"client_name exceeds maximum length of {_settings.MaxClientNameLength}."
            });
        }

        // Validate scopes
        if (request.Scope != null)
        {
            var requestedScopes = request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var scope in requestedScopes)
            {
                if (!_settings.AllowedScopes.Contains(scope))
                {
                    return (false, new ClientRegistrationError
                    {
                        Error = DcrErrorCodes.InvalidClientMetadata,
                        ErrorDescription = $"Scope '{scope}' is not allowed."
                    });
                }
            }
        }

        // Validate URIs (logo, client, policy, tos)
        var urisToValidate = new[]
        {
            (request.LogoUri, "logo_uri"),
            (request.ClientUri, "client_uri"),
            (request.PolicyUri, "policy_uri"),
            (request.TosUri, "tos_uri"),
            (request.JwksUri, "jwks_uri")
        };

        foreach (var (uri, name) in urisToValidate)
        {
            if (uri != null && !Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidClientMetadata,
                    ErrorDescription = $"Invalid {name}: must be a valid absolute URI."
                });
            }
        }

        // Validate post-logout redirect URIs
        if (request.PostLogoutRedirectUris != null)
        {
            foreach (var uri in request.PostLogoutRedirectUris)
            {
                if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
                {
                    return (false, new ClientRegistrationError
                    {
                        Error = DcrErrorCodes.InvalidRedirectUri,
                        ErrorDescription = "Invalid post_logout_redirect_uri.",
                        InvalidRedirectUri = uri
                    });
                }
            }
        }

        return (true, null);
    }

    /// <summary>
    /// Validates a single redirect URI.
    /// </summary>
    public (bool IsValid, ClientRegistrationError? Error) ValidateRedirectUri(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
        {
            return (false, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidRedirectUri,
                ErrorDescription = "redirect_uri must be a valid absolute URI.",
                InvalidRedirectUri = uri
            });
        }

        // Check for localhost
        var isLocalhost = parsedUri.Host == "localhost" || parsedUri.Host == "127.0.0.1" || parsedUri.Host == "::1";

        if (isLocalhost)
        {
            if (!_settings.AllowLocalhostRedirectUris)
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidRedirectUri,
                    ErrorDescription = "Localhost redirect URIs are not allowed.",
                    InvalidRedirectUri = uri
                });
            }

            if (parsedUri.Scheme == "http" && !_settings.AllowHttpLocalhostRedirectUris)
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidRedirectUri,
                    ErrorDescription = "HTTP localhost redirect URIs are not allowed. Use HTTPS.",
                    InvalidRedirectUri = uri
                });
            }
        }
        else
        {
            // Non-localhost must be HTTPS
            if (parsedUri.Scheme != "https")
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidRedirectUri,
                    ErrorDescription = "redirect_uri must use HTTPS scheme.",
                    InvalidRedirectUri = uri
                });
            }
        }

        // Check for fragment
        if (!string.IsNullOrEmpty(parsedUri.Fragment))
        {
            return (false, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidRedirectUri,
                ErrorDescription = "redirect_uri must not contain a fragment.",
                InvalidRedirectUri = uri
            });
        }

        // Check blocked patterns
        foreach (var pattern in _settings.BlockedRedirectUriPatterns)
        {
            if (Regex.IsMatch(uri, pattern, RegexOptions.IgnoreCase))
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidRedirectUri,
                    ErrorDescription = "redirect_uri is not allowed.",
                    InvalidRedirectUri = uri
                });
            }
        }

        // Check allowed patterns (if configured)
        if (_settings.AllowedRedirectUriPatterns.Count > 0)
        {
            var matchesAny = _settings.AllowedRedirectUriPatterns.Any(pattern =>
                Regex.IsMatch(uri, pattern, RegexOptions.IgnoreCase));

            if (!matchesAny)
            {
                return (false, new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidRedirectUri,
                    ErrorDescription = "redirect_uri does not match allowed patterns.",
                    InvalidRedirectUri = uri
                });
            }
        }

        return (true, null);
    }

    /// <summary>
    /// Validates an initial access token.
    /// </summary>
    public async Task<(bool IsValid, InitialAccessToken? Token, ClientRegistrationError? Error)> ValidateInitialAccessTokenAsync(string tokenValue)
    {
        var tokenHash = HashToken(tokenValue);

        var token = await _context.InitialAccessTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

        if (token == null)
        {
            return (false, null, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidToken,
                ErrorDescription = "Invalid initial access token."
            });
        }

        if (!token.IsValid)
        {
            string reason;
            if (token.IsRevoked)
                reason = "Token has been revoked.";
            else if (token.ExpiresAt != null && token.ExpiresAt <= DateTime.UtcNow)
                reason = "Token has expired.";
            else if (!token.IsMultiUse && token.UseCount > 0)
                reason = "Single-use token has already been used.";
            else if (token.MaxUses != null && token.UseCount >= token.MaxUses)
                reason = "Token has reached maximum uses.";
            else
                reason = "Token is no longer valid.";

            return (false, null, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidToken,
                ErrorDescription = reason
            });
        }

        return (true, token, null);
    }

    /// <summary>
    /// Validates a registration access token.
    /// </summary>
    public async Task<(bool IsValid, RegistrationAccessToken? Token, ClientRegistrationError? Error)> ValidateRegistrationAccessTokenAsync(string tokenValue, string clientId)
    {
        var tokenHash = HashToken(tokenValue);

        var token = await _context.RegistrationAccessTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && t.ClientId == clientId);

        if (token == null)
        {
            return (false, null, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidToken,
                ErrorDescription = "Invalid registration access token."
            });
        }

        if (!token.IsValid)
        {
            string reason;
            if (token.IsRevoked)
                reason = "Token has been revoked.";
            else if (token.ExpiresAt != null && token.ExpiresAt <= DateTime.UtcNow)
                reason = "Token has expired.";
            else
                reason = "Token is no longer valid.";

            return (false, null, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidToken,
                ErrorDescription = reason
            });
        }

        return (true, token, null);
    }

    /// <summary>
    /// Generates a unique client ID.
    /// </summary>
    public string GenerateClientId()
    {
        // Generate a random alphanumeric string
        var bytes = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        // Convert to base64 and make URL-safe
        var id = Convert.ToBase64String(bytes)
            .Replace("+", "")
            .Replace("/", "")
            .Replace("=", "")
            .ToLowerInvariant();

        return $"dcr_{id}";
    }

    /// <summary>
    /// Generates a client secret.
    /// </summary>
    public string GenerateClientSecret()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    /// <summary>
    /// Generates a registration access token.
    /// </summary>
    public string GenerateRegistrationAccessToken()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return "rat_" + Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    /// <summary>
    /// Generates an initial access token.
    /// </summary>
    public string GenerateInitialAccessToken()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return "iat_" + Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    /// <summary>
    /// Hashes a token for storage.
    /// </summary>
    public string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Creates a registration access token for a client.
    /// </summary>
    public async Task<(RegistrationAccessToken Entity, string PlainTextToken)> CreateRegistrationAccessTokenAsync(string clientId)
    {
        var plainTextToken = GenerateRegistrationAccessToken();
        var tokenHash = HashToken(plainTextToken);

        var entity = new RegistrationAccessToken
        {
            ClientId = clientId,
            TokenHash = tokenHash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = _settings.RegistrationAccessTokenLifetime.HasValue
                ? DateTime.UtcNow.Add(_settings.RegistrationAccessTokenLifetime.Value)
                : null
        };

        _context.RegistrationAccessTokens.Add(entity);
        await _context.SaveChangesAsync();

        return (entity, plainTextToken);
    }

    /// <summary>
    /// Creates an initial access token.
    /// </summary>
    public async Task<(InitialAccessToken Entity, string PlainTextToken)> CreateInitialAccessTokenAsync(
        string name,
        string createdById,
        string createdByEmail,
        string? description = null,
        DateTime? expiresAt = null,
        bool isMultiUse = false,
        int? maxUses = null)
    {
        var plainTextToken = GenerateInitialAccessToken();
        var tokenHash = HashToken(plainTextToken);

        var entity = new InitialAccessToken
        {
            Name = name,
            Description = description,
            TokenHash = tokenHash,
            CreatedById = createdById,
            CreatedByEmail = createdByEmail,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            IsMultiUse = isMultiUse,
            MaxUses = maxUses
        };

        _context.InitialAccessTokens.Add(entity);
        await _context.SaveChangesAsync();

        return (entity, plainTextToken);
    }

    /// <summary>
    /// Increments the use count for an initial access token.
    /// </summary>
    public async Task IncrementInitialAccessTokenUseAsync(InitialAccessToken token)
    {
        token.UseCount++;
        token.LastUsedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
    }

    /// <summary>
    /// Updates the last used timestamp for a registration access token.
    /// </summary>
    public async Task UpdateRegistrationAccessTokenLastUsedAsync(RegistrationAccessToken token)
    {
        token.LastUsedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
    }

    /// <summary>
    /// Gets the dynamic client registration metadata for a client.
    /// </summary>
    public async Task<DynamicClientRegistration?> GetDynamicClientRegistrationAsync(string clientId)
    {
        return await _context.DynamicClientRegistrations
            .Include(d => d.RegistrationAccessToken)
            .FirstOrDefaultAsync(d => d.ClientId == clientId);
    }

    /// <summary>
    /// Creates dynamic client registration metadata.
    /// </summary>
    public async Task<DynamicClientRegistration> CreateDynamicClientRegistrationAsync(
        string clientId,
        int registrationAccessTokenId,
        int? initialAccessTokenId,
        bool requiresApproval,
        string? ipAddress,
        string? userAgent,
        long clientSecretExpiresAt = 0)
    {
        var registration = new DynamicClientRegistration
        {
            ClientId = clientId,
            RegisteredAt = DateTime.UtcNow,
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ClientSecretExpiresAt = clientSecretExpiresAt,
            InitialAccessTokenId = initialAccessTokenId,
            RequiresApproval = requiresApproval,
            IsApproved = !requiresApproval,
            RegisteredFromIp = ipAddress,
            RegisteredUserAgent = userAgent
        };

        // Persist FK relationship so RFC7592 reads/updates can be correlated and admin UI can display the token state.
        _context.Entry(registration).Property("RegistrationAccessTokenId").CurrentValue = registrationAccessTokenId;

        _context.DynamicClientRegistrations.Add(registration);
        await _context.SaveChangesAsync();

        return registration;
    }

    /// <summary>
    /// Deletes dynamic client registration and associated tokens.
    /// </summary>
    public async Task DeleteDynamicClientRegistrationAsync(string clientId)
    {
        var registration = await _context.DynamicClientRegistrations
            .FirstOrDefaultAsync(d => d.ClientId == clientId);

        if (registration != null)
        {
            _context.DynamicClientRegistrations.Remove(registration);
        }

        var token = await _context.RegistrationAccessTokens
            .FirstOrDefaultAsync(t => t.ClientId == clientId);

        if (token != null)
        {
            _context.RegistrationAccessTokens.Remove(token);
        }

        await _context.SaveChangesAsync();
    }
}
