using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models.Dcr;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Controllers;

/// <summary>
/// Dynamic Client Registration endpoint per RFC 7591/7592.
/// </summary>
[ApiController]
[Route("connect/register")]
public class DynamicClientRegistrationController : ControllerBase
{
    private readonly DcrService _dcrService;
    private readonly DcrSettings _settings;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<DynamicClientRegistrationController> _logger;

    public DynamicClientRegistrationController(
        DcrService dcrService,
        IOptions<DcrSettings> settings,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictTokenManager tokenManager,
        ApplicationDbContext context,
        ILogger<DynamicClientRegistrationController> logger)
    {
        _dcrService = dcrService;
        _settings = settings.Value;
        _applicationManager = applicationManager;
        _tokenManager = tokenManager;
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Register a new OAuth client (RFC 7591).
    /// POST /connect/register
    /// </summary>
    [HttpPost]
    [Consumes("application/json")]
    [Produces("application/json")]
    public async Task<IActionResult> Register([FromBody] ClientRegistrationRequest request)
    {
        // Check if DCR is enabled
        if (!_settings.Enabled)
        {
            _logger.LogWarning("DCR request denied: feature is disabled");
            return StatusCode(403, new ClientRegistrationError
            {
                Error = DcrErrorCodes.RegistrationDisabled,
                ErrorDescription = "Dynamic client registration is disabled."
            });
        }

        // Validate initial access token if required
        InitialAccessToken? initialAccessToken = null;
        if (_settings.RequireInitialAccessToken)
        {
            var authHeader = Request.Headers.Authorization.FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Unauthorized(new ClientRegistrationError
                {
                    Error = DcrErrorCodes.InvalidToken,
                    ErrorDescription = "Initial access token required."
                });
            }

            var tokenValue = authHeader.Substring("Bearer ".Length).Trim();
            var (isValid, token, error) = await _dcrService.ValidateInitialAccessTokenAsync(tokenValue);

            if (!isValid)
            {
                _logger.LogWarning("DCR request denied: invalid initial access token");
                return Unauthorized(error);
            }

            initialAccessToken = token;
        }

        // Validate client metadata
        var (validationResult, validationError) = _dcrService.ValidateRegistrationRequest(request);
        if (!validationResult)
        {
            _logger.LogWarning("DCR request denied: validation failed - {Error}", validationError?.ErrorDescription);
            return BadRequest(validationError);
        }

        // Generate client credentials
        var clientId = _dcrService.GenerateClientId();

        // Ensure client ID is unique
        while (await _applicationManager.FindByClientIdAsync(clientId) != null)
        {
            clientId = _dcrService.GenerateClientId();
        }

        // Determine client type based on token_endpoint_auth_method
        var isConfidential = request.TokenEndpointAuthMethod != "none";
        var clientSecret = isConfidential ? _dcrService.GenerateClientSecret() : null;

        // Calculate client secret expiration
        long clientSecretExpiresAt = 0;
        if (isConfidential && !_settings.ClientSecretsNeverExpire)
        {
            clientSecretExpiresAt = DateTimeOffset.UtcNow.Add(_settings.ClientSecretLifetime).ToUnixTimeSeconds();
        }

        // Build OpenIddict application descriptor
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = request.ClientName ?? clientId,
            ClientType = isConfidential
                ? OpenIddictConstants.ClientTypes.Confidential
                : OpenIddictConstants.ClientTypes.Public
        };

        if (isConfidential && clientSecret != null)
        {
            descriptor.ClientSecret = clientSecret;
        }

        // Add redirect URIs
        if (request.RedirectUris != null)
        {
            foreach (var uri in request.RedirectUris)
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.RedirectUris.Add(parsedUri);
                }
            }
        }

        // Add post-logout redirect URIs
        if (request.PostLogoutRedirectUris != null)
        {
            foreach (var uri in request.PostLogoutRedirectUris)
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.PostLogoutRedirectUris.Add(parsedUri);
                }
            }
        }

        // Set consent type based on DCR settings
        descriptor.ConsentType = _settings.RequireAdminApproval
            ? OpenIddictConstants.ConsentTypes.Explicit
            : OpenIddictConstants.ConsentTypes.Explicit;

        // Add endpoint permissions
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        // Add grant type permissions
        var grantTypes = request.GrantTypes ?? new List<string> { "authorization_code" };
        foreach (var grantType in grantTypes)
        {
            switch (grantType)
            {
                case "authorization_code":
                    descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
                    descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
                    break;
                case "refresh_token":
                    descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
                    break;
                case "client_credentials":
                    descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
                    break;
            }
        }

        // Add scope permissions
        var scopes = request.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? new[] { "openid" };
        foreach (var scope in scopes)
        {
            if (_settings.AllowedScopes.Contains(scope))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
            }
        }

        // Add resource/audience permissions for MCP resource servers
        // This allows DCR clients to use the OAuth 2.0 resource parameter (RFC 8707)
        var mcpResources = new[]
        {
            "https://lexipro-uat.up.railway.app/mcp",
            "https://lexipro-api.rivoli.ai/mcp",
            "https://localhost:7001/mcp",
            "https://localhost:5154/mcp",
            "http://localhost:5154/mcp"
        };
        foreach (var resource in mcpResources)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Resource + resource);
        }

        // Create the client
        await _applicationManager.CreateAsync(descriptor);

        // Update initial access token usage
        if (initialAccessToken != null)
        {
            await _dcrService.IncrementInitialAccessTokenUseAsync(initialAccessToken);
        }

        // Create registration access token
        var (ratEntity, registrationAccessToken) = await _dcrService.CreateRegistrationAccessTokenAsync(clientId);

        // Create DCR metadata record
        await _dcrService.CreateDynamicClientRegistrationAsync(
            clientId,
            ratEntity.Id,
            initialAccessToken?.Id,
            _settings.RequireAdminApproval,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent.FirstOrDefault(),
            clientSecretExpiresAt);

        // Log audit
        await LogAuditAsync("DcrClientRegistered", clientId, $"Client registered via DCR: {request.ClientName ?? clientId}");

        _logger.LogInformation("New client registered via DCR: {ClientId}", clientId);

        // Build response
        var baseUri = $"{Request.Scheme}://{Request.Host}";
        var response = new ClientRegistrationResponse
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ClientSecretExpiresAt = isConfidential ? clientSecretExpiresAt : null,
            RegistrationAccessToken = registrationAccessToken,
            RegistrationClientUri = $"{baseUri}/connect/register/{clientId}",
            RedirectUris = request.RedirectUris,
            ResponseTypes = request.ResponseTypes ?? (grantTypes.Contains("authorization_code") ? new List<string> { "code" } : null),
            GrantTypes = grantTypes,
            ApplicationType = request.ApplicationType ?? "web",
            Contacts = request.Contacts,
            ClientName = request.ClientName,
            LogoUri = request.LogoUri,
            ClientUri = request.ClientUri,
            PolicyUri = request.PolicyUri,
            TosUri = request.TosUri,
            JwksUri = request.JwksUri,
            Jwks = request.Jwks,
            SoftwareId = request.SoftwareId,
            SoftwareVersion = request.SoftwareVersion,
            TokenEndpointAuthMethod = request.TokenEndpointAuthMethod ?? (isConfidential ? "client_secret_basic" : "none"),
            Scope = request.Scope ?? string.Join(" ", scopes),
            PostLogoutRedirectUris = request.PostLogoutRedirectUris
        };

        return StatusCode(201, response);
    }

    /// <summary>
    /// Read client configuration (RFC 7592).
    /// GET /connect/register/{client_id}
    /// </summary>
    [HttpGet("{clientId}")]
    [Produces("application/json")]
    public async Task<IActionResult> GetConfiguration(string clientId)
    {
        // Validate registration access token
        var (isValid, _, error) = await ValidateRegistrationAccessTokenFromHeaderAsync(clientId);
        if (!isValid)
        {
            return Unauthorized(error);
        }

        // Get client
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound(new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = "Client not found."
            });
        }

        // Get DCR metadata
        var dcrMetadata = await _dcrService.GetDynamicClientRegistrationAsync(clientId);
        if (dcrMetadata == null)
        {
            return NotFound(new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = "Client was not dynamically registered."
            });
        }

        // Build response (without client_secret)
        var response = await BuildClientResponseAsync(application, dcrMetadata, includeRegistrationToken: false);

        return Ok(response);
    }

    /// <summary>
    /// Update client configuration (RFC 7592).
    /// PUT /connect/register/{client_id}
    /// </summary>
    [HttpPut("{clientId}")]
    [Consumes("application/json")]
    [Produces("application/json")]
    public async Task<IActionResult> UpdateConfiguration(string clientId, [FromBody] ClientRegistrationRequest request)
    {
        // Validate registration access token
        var (isValid, ratToken, error) = await ValidateRegistrationAccessTokenFromHeaderAsync(clientId);
        if (!isValid)
        {
            return Unauthorized(error);
        }

        // Get client
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound(new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = "Client not found."
            });
        }

        // Get DCR metadata
        var dcrMetadata = await _dcrService.GetDynamicClientRegistrationAsync(clientId);
        if (dcrMetadata == null)
        {
            return NotFound(new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = "Client was not dynamically registered."
            });
        }

        // Validate updated metadata
        var (validationResult, validationError) = _dcrService.ValidateRegistrationRequest(request);
        if (!validationResult)
        {
            return BadRequest(validationError);
        }

        // Update the client
        var descriptor = new OpenIddictApplicationDescriptor();
        await _applicationManager.PopulateAsync(descriptor, application);

        // Update display name
        if (request.ClientName != null)
        {
            descriptor.DisplayName = request.ClientName;
        }

        // Update redirect URIs
        if (request.RedirectUris != null)
        {
            descriptor.RedirectUris.Clear();
            foreach (var uri in request.RedirectUris)
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.RedirectUris.Add(parsedUri);
                }
            }
        }

        // Update post-logout redirect URIs
        if (request.PostLogoutRedirectUris != null)
        {
            descriptor.PostLogoutRedirectUris.Clear();
            foreach (var uri in request.PostLogoutRedirectUris)
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
                {
                    descriptor.PostLogoutRedirectUris.Add(parsedUri);
                }
            }
        }

        await _applicationManager.UpdateAsync(application, descriptor);

        // Update last used timestamp
        if (ratToken != null)
        {
            await _dcrService.UpdateRegistrationAccessTokenLastUsedAsync(ratToken);
        }

        // Log audit
        await LogAuditAsync("DcrClientUpdated", clientId, $"Client updated via DCR: {request.ClientName ?? clientId}");

        _logger.LogInformation("Client updated via DCR: {ClientId}", clientId);

        // Build response
        var response = await BuildClientResponseAsync(application, dcrMetadata, includeRegistrationToken: false);

        return Ok(response);
    }

    /// <summary>
    /// Delete client registration (RFC 7592).
    /// DELETE /connect/register/{client_id}
    /// </summary>
    [HttpDelete("{clientId}")]
    public async Task<IActionResult> DeleteRegistration(string clientId)
    {
        // Validate registration access token
        var (isValid, _, error) = await ValidateRegistrationAccessTokenFromHeaderAsync(clientId);
        if (!isValid)
        {
            return Unauthorized(error);
        }

        // Get client
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound(new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = "Client not found."
            });
        }

        // Get DCR metadata
        var dcrMetadata = await _dcrService.GetDynamicClientRegistrationAsync(clientId);
        if (dcrMetadata == null)
        {
            return NotFound(new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidClientMetadata,
                ErrorDescription = "Client was not dynamically registered."
            });
        }

        // Revoke all tokens for this client
        var applicationId = await _applicationManager.GetIdAsync(application);
        if (applicationId != null)
        {
            await foreach (var token in _tokenManager.FindByApplicationIdAsync(applicationId))
            {
                await _tokenManager.TryRevokeAsync(token);
            }
        }

        // Delete DCR metadata and registration access token
        await _dcrService.DeleteDynamicClientRegistrationAsync(clientId);

        // Delete the client
        await _applicationManager.DeleteAsync(application);

        // Log audit
        await LogAuditAsync("DcrClientDeleted", clientId, $"Client deleted via DCR");

        _logger.LogInformation("Client deleted via DCR: {ClientId}", clientId);

        return NoContent();
    }

    /// <summary>
    /// Validates the registration access token from the Authorization header.
    /// </summary>
    private async Task<(bool IsValid, RegistrationAccessToken? Token, ClientRegistrationError? Error)> ValidateRegistrationAccessTokenFromHeaderAsync(string clientId)
    {
        var authHeader = Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return (false, null, new ClientRegistrationError
            {
                Error = DcrErrorCodes.InvalidToken,
                ErrorDescription = "Registration access token required."
            });
        }

        var tokenValue = authHeader.Substring("Bearer ".Length).Trim();
        return await _dcrService.ValidateRegistrationAccessTokenAsync(tokenValue, clientId);
    }

    /// <summary>
    /// Builds a client response from the application and DCR metadata.
    /// </summary>
    private async Task<ClientRegistrationResponse> BuildClientResponseAsync(
        object application,
        DynamicClientRegistration dcrMetadata,
        bool includeRegistrationToken)
    {
        var clientId = await _applicationManager.GetClientIdAsync(application);
        var displayName = await _applicationManager.GetDisplayNameAsync(application);
        var clientType = await _applicationManager.GetClientTypeAsync(application);
        var redirectUris = await _applicationManager.GetRedirectUrisAsync(application);
        var postLogoutRedirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(application);
        var permissions = await _applicationManager.GetPermissionsAsync(application);

        var isConfidential = clientType == OpenIddictConstants.ClientTypes.Confidential;

        // Extract grant types from permissions
        var grantTypes = new List<string>();
        if (permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode))
            grantTypes.Add("authorization_code");
        if (permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken))
            grantTypes.Add("refresh_token");
        if (permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials))
            grantTypes.Add("client_credentials");

        // Extract scopes from permissions
        var scopes = permissions
            .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope))
            .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length))
            .ToList();

        var baseUri = $"{Request.Scheme}://{Request.Host}";

        return new ClientRegistrationResponse
        {
            ClientId = clientId!,
            ClientIdIssuedAt = dcrMetadata.ClientIdIssuedAt,
            ClientSecretExpiresAt = isConfidential ? dcrMetadata.ClientSecretExpiresAt : null,
            RegistrationClientUri = $"{baseUri}/connect/register/{clientId}",
            RedirectUris = redirectUris.Select(u => u.ToString()).ToList(),
            ResponseTypes = grantTypes.Contains("authorization_code") ? new List<string> { "code" } : null,
            GrantTypes = grantTypes,
            ClientName = displayName,
            TokenEndpointAuthMethod = isConfidential ? "client_secret_basic" : "none",
            Scope = string.Join(" ", scopes),
            PostLogoutRedirectUris = postLogoutRedirectUris.Select(u => u.ToString()).ToList()
        };
    }

    /// <summary>
    /// Logs an audit entry for DCR operations.
    /// </summary>
    private async Task LogAuditAsync(string action, string clientId, string details)
    {
        var auditLog = new AuditLog
        {
            Action = action,
            PerformedById = "system",
            PerformedByEmail = "dcr@system",
            Details = $"Client ID: {clientId}. {details}",
            PerformedAt = DateTime.UtcNow,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();
    }
}
