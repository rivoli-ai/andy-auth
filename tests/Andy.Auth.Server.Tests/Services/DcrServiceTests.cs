using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models.Dcr;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Andy.Auth.Server.Tests.Services;

public class DcrServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<ILogger<DcrService>> _loggerMock;
    private readonly DcrSettings _settings;
    private readonly DcrService _service;

    public DcrServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _loggerMock = new Mock<ILogger<DcrService>>();

        _settings = new DcrSettings
        {
            Enabled = true,
            RequireInitialAccessToken = true,
            AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token", "client_credentials" },
            AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access" },
            AllowLocalhostRedirectUris = true,
            AllowHttpLocalhostRedirectUris = true,
            MaxRedirectUrisPerClient = 10,
            MaxClientNameLength = 200,
            BlockedRedirectUriPatterns = new List<string>(),
            AllowedRedirectUriPatterns = new List<string>()
        };

        var optionsMock = new Mock<IOptions<DcrSettings>>();
        optionsMock.Setup(x => x.Value).Returns(_settings);

        _service = new DcrService(_context, optionsMock.Object, _loggerMock.Object);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== ValidateRedirectUri Tests ====================

    [Fact]
    public void ValidateRedirectUri_ValidHttpsUri_ReturnsValid()
    {
        // Act
        var (isValid, error) = _service.ValidateRedirectUri("https://example.com/callback");

        // Assert
        isValid.Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void ValidateRedirectUri_HttpLocalhost_AllowedWhenConfigured()
    {
        // Act
        var (isValid, error) = _service.ValidateRedirectUri("http://localhost:3000/callback");

        // Assert
        isValid.Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void ValidateRedirectUri_HttpLocalhost_RejectedWhenNotConfigured()
    {
        // Arrange
        _settings.AllowHttpLocalhostRedirectUris = false;

        // Act
        var (isValid, error) = _service.ValidateRedirectUri("http://localhost:3000/callback");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
        error.ErrorDescription.Should().Contain("HTTP localhost");
    }

    [Fact]
    public void ValidateRedirectUri_Localhost_RejectedWhenNotConfigured()
    {
        // Arrange
        _settings.AllowLocalhostRedirectUris = false;

        // Act
        var (isValid, error) = _service.ValidateRedirectUri("https://localhost:3000/callback");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
    }

    [Fact]
    public void ValidateRedirectUri_HttpNonLocalhost_Rejected()
    {
        // Act
        var (isValid, error) = _service.ValidateRedirectUri("http://example.com/callback");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
        error.ErrorDescription.Should().Contain("HTTPS");
    }

    [Fact]
    public void ValidateRedirectUri_WithFragment_Rejected()
    {
        // Act
        var (isValid, error) = _service.ValidateRedirectUri("https://example.com/callback#fragment");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
        error.ErrorDescription.Should().Contain("fragment");
    }

    [Fact]
    public void ValidateRedirectUri_InvalidUri_Rejected()
    {
        // Act
        var (isValid, error) = _service.ValidateRedirectUri("not-a-valid-uri");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
        error.InvalidRedirectUri.Should().Be("not-a-valid-uri");
    }

    [Fact]
    public void ValidateRedirectUri_CustomScheme_Allowed()
    {
        // Act - Custom URI schemes for native apps
        var (isValid, error) = _service.ValidateRedirectUri("vscode://saoudrizwan.claude-dev/callback");

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateRedirectUri_BlockedPattern_Rejected()
    {
        // Arrange
        _settings.BlockedRedirectUriPatterns = new List<string> { @"evil\.com" };

        // Act
        var (isValid, error) = _service.ValidateRedirectUri("https://evil.com/callback");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
    }

    [Fact]
    public void ValidateRedirectUri_AllowedPattern_Validated()
    {
        // Arrange
        _settings.AllowedRedirectUriPatterns = new List<string> { @"https://allowed\.com/.*" };

        // Act
        var (isValidAllowed, _) = _service.ValidateRedirectUri("https://allowed.com/callback");
        var (isValidNotAllowed, error) = _service.ValidateRedirectUri("https://other.com/callback");

        // Assert
        isValidAllowed.Should().BeTrue();
        isValidNotAllowed.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("allowed patterns");
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080/callback")]
    [InlineData("http://[::1]:8080/callback")]
    public void ValidateRedirectUri_LoopbackAddresses_TreatedAsLocalhost(string uri)
    {
        // Act
        var (isValid, _) = _service.ValidateRedirectUri(uri);

        // Assert
        isValid.Should().BeTrue();
    }

    // ==================== ValidateRegistrationRequest Tests ====================

    [Fact]
    public void ValidateRegistrationRequest_ValidRequest_ReturnsValid()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            RedirectUris = new List<string> { "https://example.com/callback" },
            GrantTypes = new List<string> { "authorization_code" },
            ResponseTypes = new List<string> { "code" },
            ClientName = "Test App"
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void ValidateRegistrationRequest_TooManyRedirectUris_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            RedirectUris = Enumerable.Range(1, 15).Select(i => $"https://example.com/callback{i}").ToList()
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("Maximum");
    }

    [Fact]
    public void ValidateRegistrationRequest_InvalidGrantType_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            GrantTypes = new List<string> { "password" } // Not allowed
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("password");
    }

    [Fact]
    public void ValidateRegistrationRequest_AuthCodeWithoutRedirectUri_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            GrantTypes = new List<string> { "authorization_code" }
            // No redirect_uris
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("redirect_uris is required");
    }

    [Fact]
    public void ValidateRegistrationRequest_ResponseTypeCodeWithoutAuthCodeGrant_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            ResponseTypes = new List<string> { "code" },
            GrantTypes = new List<string> { "client_credentials" }
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("response_type 'code' requires");
    }

    [Theory]
    [InlineData("web")]
    [InlineData("native")]
    [InlineData("service")]
    [InlineData("WEB")]
    public void ValidateRegistrationRequest_ValidApplicationType_Accepted(string appType)
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            ApplicationType = appType
        };

        // Act
        var (isValid, _) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateRegistrationRequest_InvalidApplicationType_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            ApplicationType = "invalid"
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("application_type");
    }

    [Theory]
    [InlineData("client_secret_basic")]
    [InlineData("client_secret_post")]
    [InlineData("none")]
    public void ValidateRegistrationRequest_ValidTokenEndpointAuthMethod_Accepted(string method)
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            TokenEndpointAuthMethod = method
        };

        // Act
        var (isValid, _) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateRegistrationRequest_InvalidTokenEndpointAuthMethod_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            TokenEndpointAuthMethod = "private_key_jwt"
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
    }

    [Fact]
    public void ValidateRegistrationRequest_ClientNameTooLong_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            ClientName = new string('x', 201)
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("client_name");
    }

    [Fact]
    public void ValidateRegistrationRequest_InvalidScope_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            Scope = "openid custom_scope"
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("custom_scope");
    }

    [Fact]
    public void ValidateRegistrationRequest_InvalidLogoUri_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            LogoUri = "not-a-valid-uri"
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
        error.ErrorDescription.Should().Contain("logo_uri");
    }

    [Theory]
    [InlineData("client_uri")]
    [InlineData("policy_uri")]
    [InlineData("tos_uri")]
    [InlineData("jwks_uri")]
    public void ValidateRegistrationRequest_ValidOptionalUris_Accepted(string uriType)
    {
        // Arrange
        var request = new ClientRegistrationRequest();
        var validUri = "https://example.com/path";

        switch (uriType)
        {
            case "client_uri": request.ClientUri = validUri; break;
            case "policy_uri": request.PolicyUri = validUri; break;
            case "tos_uri": request.TosUri = validUri; break;
            case "jwks_uri": request.JwksUri = validUri; break;
        }

        // Act
        var (isValid, _) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeTrue();
    }

    [Fact]
    public void ValidateRegistrationRequest_InvalidPostLogoutRedirectUri_Rejected()
    {
        // Arrange
        var request = new ClientRegistrationRequest
        {
            PostLogoutRedirectUris = new List<string> { "not-valid" }
        };

        // Act
        var (isValid, error) = _service.ValidateRegistrationRequest(request);

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
        error.ErrorDescription.Should().Contain("post_logout_redirect_uri");
    }

    // ==================== ValidateInitialAccessTokenAsync Tests ====================

    [Fact]
    public async Task ValidateInitialAccessTokenAsync_ValidToken_ReturnsValid()
    {
        // Arrange
        var (entity, plainText) = await _service.CreateInitialAccessTokenAsync(
            "Test Token", "admin-1", "admin@test.com", isMultiUse: true);

        // Act
        var (isValid, token, error) = await _service.ValidateInitialAccessTokenAsync(plainText);

        // Assert
        isValid.Should().BeTrue();
        token.Should().NotBeNull();
        token!.Id.Should().Be(entity.Id);
        error.Should().BeNull();
    }

    [Fact]
    public async Task ValidateInitialAccessTokenAsync_InvalidToken_ReturnsError()
    {
        // Act
        var (isValid, token, error) = await _service.ValidateInitialAccessTokenAsync("invalid-token");

        // Assert
        isValid.Should().BeFalse();
        token.Should().BeNull();
        error!.Error.Should().Be(DcrErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task ValidateInitialAccessTokenAsync_RevokedToken_ReturnsError()
    {
        // Arrange
        var (entity, plainText) = await _service.CreateInitialAccessTokenAsync(
            "Test Token", "admin-1", "admin@test.com");
        entity.IsRevoked = true;
        await _context.SaveChangesAsync();

        // Act
        var (isValid, _, error) = await _service.ValidateInitialAccessTokenAsync(plainText);

        // Assert
        isValid.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("revoked");
    }

    [Fact]
    public async Task ValidateInitialAccessTokenAsync_ExpiredToken_ReturnsError()
    {
        // Arrange
        var (entity, plainText) = await _service.CreateInitialAccessTokenAsync(
            "Test Token", "admin-1", "admin@test.com",
            expiresAt: DateTime.UtcNow.AddHours(-1));

        // Act
        var (isValid, _, error) = await _service.ValidateInitialAccessTokenAsync(plainText);

        // Assert
        isValid.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("expired");
    }

    [Fact]
    public async Task ValidateInitialAccessTokenAsync_SingleUseAlreadyUsed_ReturnsError()
    {
        // Arrange
        var (entity, plainText) = await _service.CreateInitialAccessTokenAsync(
            "Test Token", "admin-1", "admin@test.com", isMultiUse: false);
        await _service.IncrementInitialAccessTokenUseAsync(entity);

        // Act
        var (isValid, _, error) = await _service.ValidateInitialAccessTokenAsync(plainText);

        // Assert
        isValid.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("already been used");
    }

    [Fact]
    public async Task ValidateInitialAccessTokenAsync_MaxUsesReached_ReturnsError()
    {
        // Arrange
        var (entity, plainText) = await _service.CreateInitialAccessTokenAsync(
            "Test Token", "admin-1", "admin@test.com", isMultiUse: true, maxUses: 2);
        entity.UseCount = 2;
        await _context.SaveChangesAsync();

        // Act
        var (isValid, _, error) = await _service.ValidateInitialAccessTokenAsync(plainText);

        // Assert
        isValid.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("maximum uses");
    }

    // ==================== ValidateRegistrationAccessTokenAsync Tests ====================

    [Fact]
    public async Task ValidateRegistrationAccessTokenAsync_ValidToken_ReturnsValid()
    {
        // Arrange
        var clientId = "dcr_test123";
        var (entity, plainText) = await _service.CreateRegistrationAccessTokenAsync(clientId);

        // Act
        var (isValid, token, error) = await _service.ValidateRegistrationAccessTokenAsync(plainText, clientId);

        // Assert
        isValid.Should().BeTrue();
        token.Should().NotBeNull();
        token!.Id.Should().Be(entity.Id);
        error.Should().BeNull();
    }

    [Fact]
    public async Task ValidateRegistrationAccessTokenAsync_WrongClient_ReturnsError()
    {
        // Arrange
        var (_, plainText) = await _service.CreateRegistrationAccessTokenAsync("dcr_client1");

        // Act
        var (isValid, _, error) = await _service.ValidateRegistrationAccessTokenAsync(plainText, "dcr_client2");

        // Assert
        isValid.Should().BeFalse();
        error!.Error.Should().Be(DcrErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task ValidateRegistrationAccessTokenAsync_RevokedToken_ReturnsError()
    {
        // Arrange
        var clientId = "dcr_test";
        var (entity, plainText) = await _service.CreateRegistrationAccessTokenAsync(clientId);
        entity.IsRevoked = true;
        await _context.SaveChangesAsync();

        // Act
        var (isValid, _, error) = await _service.ValidateRegistrationAccessTokenAsync(plainText, clientId);

        // Assert
        isValid.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("revoked");
    }

    [Fact]
    public async Task ValidateRegistrationAccessTokenAsync_ExpiredToken_ReturnsError()
    {
        // Arrange
        var clientId = "dcr_test";
        var (entity, plainText) = await _service.CreateRegistrationAccessTokenAsync(clientId);
        entity.ExpiresAt = DateTime.UtcNow.AddHours(-1);
        await _context.SaveChangesAsync();

        // Act
        var (isValid, _, error) = await _service.ValidateRegistrationAccessTokenAsync(plainText, clientId);

        // Assert
        isValid.Should().BeFalse();
        error!.ErrorDescription.Should().Contain("expired");
    }

    // ==================== Token Generation Tests ====================

    [Fact]
    public void GenerateClientId_ReturnsUniqueIds()
    {
        // Act
        var id1 = _service.GenerateClientId();
        var id2 = _service.GenerateClientId();

        // Assert
        id1.Should().StartWith("dcr_");
        id2.Should().StartWith("dcr_");
        id1.Should().NotBe(id2);
    }

    [Fact]
    public void GenerateClientId_IsUrlSafe()
    {
        // Act
        var id = _service.GenerateClientId();

        // Assert
        id.Should().NotContain("+");
        id.Should().NotContain("/");
        id.Should().NotContain("=");
    }

    [Fact]
    public void GenerateClientSecret_ReturnsSecureSecret()
    {
        // Act
        var secret = _service.GenerateClientSecret();

        // Assert
        secret.Should().HaveLength(43); // Base64 encoded 32 bytes without padding
        secret.Should().NotContain("+");
        secret.Should().NotContain("/");
    }

    [Fact]
    public void GenerateRegistrationAccessToken_HasCorrectPrefix()
    {
        // Act
        var token = _service.GenerateRegistrationAccessToken();

        // Assert
        token.Should().StartWith("rat_");
    }

    [Fact]
    public void GenerateInitialAccessToken_HasCorrectPrefix()
    {
        // Act
        var token = _service.GenerateInitialAccessToken();

        // Assert
        token.Should().StartWith("iat_");
    }

    // ==================== HashToken Tests ====================

    [Fact]
    public void HashToken_ReturnsConsistentHash()
    {
        // Arrange
        var token = "test-token-123";

        // Act
        var hash1 = _service.HashToken(token);
        var hash2 = _service.HashToken(token);

        // Assert
        hash1.Should().Be(hash2);
        hash1.Should().HaveLength(64); // SHA-256 = 32 bytes = 64 hex chars
    }

    [Fact]
    public void HashToken_DifferentTokensProduceDifferentHashes()
    {
        // Act
        var hash1 = _service.HashToken("token-1");
        var hash2 = _service.HashToken("token-2");

        // Assert
        hash1.Should().NotBe(hash2);
    }

    // ==================== Token Creation Tests ====================

    [Fact]
    public async Task CreateRegistrationAccessTokenAsync_PersistsToken()
    {
        // Arrange
        var clientId = "dcr_test";

        // Act
        var (entity, plainText) = await _service.CreateRegistrationAccessTokenAsync(clientId);

        // Assert
        entity.Should().NotBeNull();
        entity.ClientId.Should().Be(clientId);
        entity.TokenHash.Should().Be(_service.HashToken(plainText));
        entity.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));

        var saved = await _context.RegistrationAccessTokens.FindAsync(entity.Id);
        saved.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateInitialAccessTokenAsync_PersistsToken()
    {
        // Arrange
        var name = "Dev Token";
        var description = "For development";
        var createdById = "admin-1";
        var createdByEmail = "admin@test.com";
        var expiresAt = DateTime.UtcNow.AddDays(30);

        // Act
        var (entity, plainText) = await _service.CreateInitialAccessTokenAsync(
            name, createdById, createdByEmail, description, expiresAt, isMultiUse: true, maxUses: 5);

        // Assert
        entity.Name.Should().Be(name);
        entity.Description.Should().Be(description);
        entity.CreatedById.Should().Be(createdById);
        entity.CreatedByEmail.Should().Be(createdByEmail);
        entity.ExpiresAt.Should().Be(expiresAt);
        entity.IsMultiUse.Should().BeTrue();
        entity.MaxUses.Should().Be(5);
        entity.UseCount.Should().Be(0);
        entity.TokenHash.Should().Be(_service.HashToken(plainText));

        var saved = await _context.InitialAccessTokens.FindAsync(entity.Id);
        saved.Should().NotBeNull();
    }

    // ==================== Token Use Tracking Tests ====================

    [Fact]
    public async Task IncrementInitialAccessTokenUseAsync_IncrementsCount()
    {
        // Arrange
        var (entity, _) = await _service.CreateInitialAccessTokenAsync(
            "Test", "admin", "admin@test.com", isMultiUse: true);

        // Act
        await _service.IncrementInitialAccessTokenUseAsync(entity);
        await _service.IncrementInitialAccessTokenUseAsync(entity);

        // Assert
        var updated = await _context.InitialAccessTokens.FindAsync(entity.Id);
        updated!.UseCount.Should().Be(2);
        updated.LastUsedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task UpdateRegistrationAccessTokenLastUsedAsync_UpdatesTimestamp()
    {
        // Arrange
        var (entity, _) = await _service.CreateRegistrationAccessTokenAsync("dcr_test");

        // Act
        await _service.UpdateRegistrationAccessTokenLastUsedAsync(entity);

        // Assert
        var updated = await _context.RegistrationAccessTokens.FindAsync(entity.Id);
        updated!.LastUsedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    // ==================== DCR Metadata Tests ====================

    [Fact]
    public async Task GetDynamicClientRegistrationAsync_ReturnsRegistration()
    {
        // Arrange
        var clientId = "dcr_test";
        var (rat, _) = await _service.CreateRegistrationAccessTokenAsync(clientId);
        await _service.CreateDynamicClientRegistrationAsync(
            clientId, rat.Id, null, false, "192.168.1.1", "Test Agent");

        // Act
        var registration = await _service.GetDynamicClientRegistrationAsync(clientId);

        // Assert
        registration.Should().NotBeNull();
        registration!.ClientId.Should().Be(clientId);
        registration.RegisteredFromIp.Should().Be("192.168.1.1");
        registration.RegisteredUserAgent.Should().Be("Test Agent");
        registration.IsApproved.Should().BeTrue();
    }

    [Fact]
    public async Task GetDynamicClientRegistrationAsync_ReturnsNullForNonExistent()
    {
        // Act
        var registration = await _service.GetDynamicClientRegistrationAsync("non-existent");

        // Assert
        registration.Should().BeNull();
    }

    [Fact]
    public async Task CreateDynamicClientRegistrationAsync_CreatesWithApprovalRequired()
    {
        // Arrange
        var clientId = "dcr_test";
        var (rat, _) = await _service.CreateRegistrationAccessTokenAsync(clientId);

        // Act
        var registration = await _service.CreateDynamicClientRegistrationAsync(
            clientId, rat.Id, null, requiresApproval: true, null, null);

        // Assert
        registration.RequiresApproval.Should().BeTrue();
        registration.IsApproved.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteDynamicClientRegistrationAsync_RemovesRegistrationAndToken()
    {
        // Arrange
        var clientId = "dcr_test";
        var (rat, _) = await _service.CreateRegistrationAccessTokenAsync(clientId);
        await _service.CreateDynamicClientRegistrationAsync(clientId, rat.Id, null, false, null, null);

        // Verify they exist
        (await _context.DynamicClientRegistrations.AnyAsync(d => d.ClientId == clientId)).Should().BeTrue();
        (await _context.RegistrationAccessTokens.AnyAsync(t => t.ClientId == clientId)).Should().BeTrue();

        // Act
        await _service.DeleteDynamicClientRegistrationAsync(clientId);

        // Assert
        (await _context.DynamicClientRegistrations.AnyAsync(d => d.ClientId == clientId)).Should().BeFalse();
        (await _context.RegistrationAccessTokens.AnyAsync(t => t.ClientId == clientId)).Should().BeFalse();
    }

    [Fact]
    public async Task DeleteDynamicClientRegistrationAsync_HandlesNonExistent()
    {
        // Act & Assert - Should not throw
        await _service.DeleteDynamicClientRegistrationAsync("non-existent");
    }
}
