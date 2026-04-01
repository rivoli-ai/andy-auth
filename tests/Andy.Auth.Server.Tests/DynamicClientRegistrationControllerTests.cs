using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Models.Dcr;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using System.Collections.Immutable;

namespace Andy.Auth.Server.Tests;

public class DynamicClientRegistrationControllerTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<IOpenIddictApplicationManager> _applicationManagerMock;
    private readonly Mock<IOpenIddictTokenManager> _tokenManagerMock;
    private readonly Mock<ILogger<DynamicClientRegistrationController>> _loggerMock;
    private readonly Mock<ILogger<DcrService>> _dcrLoggerMock;
    private readonly DcrSettings _settings;
    private readonly DcrService _dcrService;
    private readonly DynamicClientRegistrationController _controller;

    public DynamicClientRegistrationControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        _applicationManagerMock = new Mock<IOpenIddictApplicationManager>();
        _tokenManagerMock = new Mock<IOpenIddictTokenManager>();
        _loggerMock = new Mock<ILogger<DynamicClientRegistrationController>>();
        _dcrLoggerMock = new Mock<ILogger<DcrService>>();

        _settings = new DcrSettings
        {
            Enabled = true,
            RequireInitialAccessToken = false,
            RequireAdminApproval = false,
            AllowedGrantTypes = new List<string> { "authorization_code", "refresh_token" },
            AllowedScopes = new List<string> { "openid", "profile", "email" },
            ClientSecretLifetime = TimeSpan.FromDays(365),
            ClientSecretsNeverExpire = false,
            AllowLocalhostRedirectUris = true,
            AllowHttpLocalhostRedirectUris = true
        };

        var settingsOptions = Options.Create(_settings);

        _dcrService = new DcrService(_context, settingsOptions, _dcrLoggerMock.Object);

        _controller = new DynamicClientRegistrationController(
            _dcrService,
            settingsOptions,
            _applicationManagerMock.Object,
            _tokenManagerMock.Object,
            _context,
            _loggerMock.Object);

        SetupHttpContext();
    }

    private void SetupHttpContext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Scheme = "https";
        httpContext.Request.Host = new HostString("auth.example.com");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    // ==================== Register Tests ====================

    [Fact]
    public async Task Register_DcrDisabled_Returns403()
    {
        // Arrange
        var disabledSettings = new DcrSettings { Enabled = false };
        var controller = CreateControllerWithSettings(disabledSettings);
        var request = new ClientRegistrationRequest
        {
            ClientName = "Test App",
            RedirectUris = new List<string> { "https://example.com/callback" }
        };

        // Act
        var result = await controller.Register(request);

        // Assert
        var statusResult = result.Should().BeOfType<ObjectResult>().Subject;
        statusResult.StatusCode.Should().Be(403);
        var error = statusResult.Value.Should().BeOfType<ClientRegistrationError>().Subject;
        error.Error.Should().Be(DcrErrorCodes.RegistrationDisabled);
    }

    [Fact]
    public async Task Register_RequiresTokenButMissing_Returns401()
    {
        // Arrange
        var tokenRequiredSettings = new DcrSettings
        {
            Enabled = true,
            RequireInitialAccessToken = true,
            AllowedGrantTypes = new List<string> { "authorization_code" },
            AllowedScopes = new List<string> { "openid" }
        };
        var controller = CreateControllerWithSettings(tokenRequiredSettings);
        var request = new ClientRegistrationRequest
        {
            ClientName = "Test App",
            RedirectUris = new List<string> { "https://example.com/callback" }
        };

        // Act
        var result = await controller.Register(request);

        // Assert
        var unauthorizedResult = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        var error = unauthorizedResult.Value.Should().BeOfType<ClientRegistrationError>().Subject;
        error.Error.Should().Be(DcrErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task Register_ValidRequest_ReturnsCreatedClient()
    {
        // Arrange
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);
        _applicationManagerMock.Setup(x => x.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<object>(new object()));

        var request = new ClientRegistrationRequest
        {
            ClientName = "Test App",
            RedirectUris = new List<string> { "https://example.com/callback" },
            GrantTypes = new List<string> { "authorization_code" },
            TokenEndpointAuthMethod = "client_secret_basic"
        };

        // Act
        var result = await _controller.Register(request);

        // Assert
        var statusResult = result.Should().BeOfType<ObjectResult>().Subject;
        statusResult.StatusCode.Should().Be(201);
        var response = statusResult.Value.Should().BeOfType<ClientRegistrationResponse>().Subject;
        response.ClientId.Should().NotBeNullOrEmpty();
        response.ClientSecret.Should().NotBeNullOrEmpty();
        response.RegistrationAccessToken.Should().NotBeNullOrEmpty();
        response.ClientName.Should().Be("Test App");
    }

    [Fact]
    public async Task Register_PublicClient_ReturnsNoSecret()
    {
        // Arrange
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);
        _applicationManagerMock.Setup(x => x.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<object>(new object()));

        var request = new ClientRegistrationRequest
        {
            ClientName = "Public App",
            RedirectUris = new List<string> { "https://example.com/callback" },
            TokenEndpointAuthMethod = "none"
        };

        // Act
        var result = await _controller.Register(request);

        // Assert
        var statusResult = result.Should().BeOfType<ObjectResult>().Subject;
        statusResult.StatusCode.Should().Be(201);
        var response = statusResult.Value.Should().BeOfType<ClientRegistrationResponse>().Subject;
        response.ClientSecret.Should().BeNull();
    }

    [Fact]
    public async Task Register_InvalidRedirectUri_ReturnsBadRequest()
    {
        // Arrange
        var strictSettings = new DcrSettings
        {
            Enabled = true,
            AllowedGrantTypes = new List<string> { "authorization_code" },
            AllowedScopes = new List<string> { "openid" },
            AllowLocalhostRedirectUris = false
        };
        var controller = CreateControllerWithSettings(strictSettings);

        var request = new ClientRegistrationRequest
        {
            ClientName = "Test App",
            RedirectUris = new List<string> { "http://localhost/callback" }, // HTTP localhost not allowed
            ApplicationType = "web"
        };

        // Act
        var result = await controller.Register(request);

        // Assert
        var badRequest = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var error = badRequest.Value.Should().BeOfType<ClientRegistrationError>().Subject;
        error.Error.Should().Be(DcrErrorCodes.InvalidRedirectUri);
    }

    [Fact]
    public async Task Register_WithValidInitialAccessToken_Succeeds()
    {
        // Arrange
        var (token, tokenValue) = await CreateInitialAccessTokenAsync();

        var tokenRequiredSettings = new DcrSettings
        {
            Enabled = true,
            RequireInitialAccessToken = true,
            AllowedGrantTypes = new List<string> { "authorization_code" },
            AllowedScopes = new List<string> { "openid", "profile", "email" },
            AllowLocalhostRedirectUris = true
        };
        var controller = CreateControllerWithSettings(tokenRequiredSettings);
        controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {tokenValue}";

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);
        _applicationManagerMock.Setup(x => x.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<object>(new object()));

        var request = new ClientRegistrationRequest
        {
            ClientName = "Token Auth App",
            RedirectUris = new List<string> { "https://example.com/callback" }
        };

        // Act
        var result = await controller.Register(request);

        // Assert
        var statusResult = result.Should().BeOfType<ObjectResult>().Subject;
        statusResult.StatusCode.Should().Be(201);
    }

    // ==================== GetConfiguration Tests ====================

    [Fact]
    public async Task GetConfiguration_MissingToken_Returns401()
    {
        // Act
        var result = await _controller.GetConfiguration("test-client");

        // Assert
        var unauthorizedResult = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        var error = unauthorizedResult.Value.Should().BeOfType<ClientRegistrationError>().Subject;
        error.Error.Should().Be(DcrErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task GetConfiguration_ClientNotFound_Returns404()
    {
        // Arrange
        var (dcr, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        // Act
        var result = await _controller.GetConfiguration(clientId);

        // Assert
        var notFoundResult = result.Should().BeOfType<NotFoundObjectResult>().Subject;
        var error = notFoundResult.Value.Should().BeOfType<ClientRegistrationError>().Subject;
        error.Error.Should().Be(DcrErrorCodes.InvalidClientMetadata);
    }

    [Fact]
    public async Task GetConfiguration_ValidToken_ReturnsClientConfig()
    {
        // Arrange
        var (dcr, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        var mockApplication = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetClientIdAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync(clientId);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Test Client");
        _applicationManagerMock.Setup(x => x.GetClientTypeAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
        _applicationManagerMock.Setup(x => x.GetRedirectUrisAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<ImmutableArray<string>>(ImmutableArray.Create("https://example.com/callback")));
        _applicationManagerMock.Setup(x => x.GetPostLogoutRedirectUrisAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<ImmutableArray<string>>(ImmutableArray<string>.Empty));
        _applicationManagerMock.Setup(x => x.GetPermissionsAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<ImmutableArray<string>>(ImmutableArray.Create(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid"
            )));

        // Act
        var result = await _controller.GetConfiguration(clientId);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ClientRegistrationResponse>().Subject;
        response.ClientId.Should().Be(clientId);
        response.ClientName.Should().Be("Test Client");
    }

    // ==================== UpdateConfiguration Tests ====================

    [Fact]
    public async Task UpdateConfiguration_MissingToken_Returns401()
    {
        // Arrange
        var request = new ClientRegistrationRequest { ClientName = "Updated Name" };

        // Act
        var result = await _controller.UpdateConfiguration("test-client", request);

        // Assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task UpdateConfiguration_ClientNotFound_Returns404()
    {
        // Arrange
        var (_, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        var request = new ClientRegistrationRequest { ClientName = "Updated Name" };

        // Act
        var result = await _controller.UpdateConfiguration(clientId, request);

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task UpdateConfiguration_ValidRequest_UpdatesClient()
    {
        // Arrange
        var (dcr, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        var mockApplication = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), mockApplication, It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);
        _applicationManagerMock.Setup(x => x.UpdateAsync(mockApplication, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);
        _applicationManagerMock.Setup(x => x.GetClientIdAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync(clientId);
        _applicationManagerMock.Setup(x => x.GetDisplayNameAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("Updated Name");
        _applicationManagerMock.Setup(x => x.GetClientTypeAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
        _applicationManagerMock.Setup(x => x.GetRedirectUrisAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<ImmutableArray<string>>(ImmutableArray.Create("https://example.com/new-callback")));
        _applicationManagerMock.Setup(x => x.GetPostLogoutRedirectUrisAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<ImmutableArray<string>>(ImmutableArray<string>.Empty));
        _applicationManagerMock.Setup(x => x.GetPermissionsAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(new ValueTask<ImmutableArray<string>>(ImmutableArray.Create(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode
            )));

        var request = new ClientRegistrationRequest
        {
            ClientName = "Updated Name",
            RedirectUris = new List<string> { "https://example.com/new-callback" }
        };

        // Act
        var result = await _controller.UpdateConfiguration(clientId, request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ClientRegistrationResponse>().Subject;
        response.ClientName.Should().Be("Updated Name");
    }

    // ==================== DeleteRegistration Tests ====================

    [Fact]
    public async Task DeleteRegistration_MissingToken_Returns401()
    {
        // Act
        var result = await _controller.DeleteRegistration("test-client");

        // Assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task DeleteRegistration_ClientNotFound_Returns404()
    {
        // Arrange
        var (_, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        // Act
        var result = await _controller.DeleteRegistration(clientId);

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task DeleteRegistration_ValidRequest_DeletesClient()
    {
        // Arrange
        var (dcr, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        var mockApplication = new object();
        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetIdAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("app-id");
        _applicationManagerMock.Setup(x => x.DeleteAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);

        // Setup empty token enumerable
        _tokenManagerMock.Setup(x => x.FindByApplicationIdAsync("app-id", It.IsAny<CancellationToken>()))
            .Returns(EmptyAsyncEnumerable<object>());

        // Act
        var result = await _controller.DeleteRegistration(clientId);

        // Assert
        result.Should().BeOfType<NoContentResult>();

        // Verify DCR record was deleted
        var deletedDcr = await _context.DynamicClientRegistrations
            .FirstOrDefaultAsync(d => d.ClientId == clientId);
        deletedDcr.Should().BeNull();
    }

    [Fact]
    public async Task DeleteRegistration_RevokesAllClientTokens()
    {
        // Arrange
        var (dcr, rat, clientId) = await CreateRegisteredClientAsync();
        _controller.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {rat}";

        var mockApplication = new object();
        var mockTokens = new List<object> { new object(), new object() };

        _applicationManagerMock.Setup(x => x.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockApplication);
        _applicationManagerMock.Setup(x => x.GetIdAsync(mockApplication, It.IsAny<CancellationToken>()))
            .ReturnsAsync("app-id");
        _applicationManagerMock.Setup(x => x.DeleteAsync(mockApplication, It.IsAny<CancellationToken>()))
            .Returns(ValueTask.CompletedTask);

        _tokenManagerMock.Setup(x => x.FindByApplicationIdAsync("app-id", It.IsAny<CancellationToken>()))
            .Returns(ToAsyncEnumerable(mockTokens));
        _tokenManagerMock.Setup(x => x.TryRevokeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteRegistration(clientId);

        // Assert
        result.Should().BeOfType<NoContentResult>();
        _tokenManagerMock.Verify(x => x.TryRevokeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    // ==================== Helper Methods ====================

    private DynamicClientRegistrationController CreateControllerWithSettings(DcrSettings settings)
    {
        var settingsOptions = Options.Create(settings);
        var dcrService = new DcrService(_context, settingsOptions, _dcrLoggerMock.Object);

        var controller = new DynamicClientRegistrationController(
            dcrService,
            settingsOptions,
            _applicationManagerMock.Object,
            _tokenManagerMock.Object,
            _context,
            _loggerMock.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Scheme = "https";
        httpContext.Request.Host = new HostString("auth.example.com");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        return controller;
    }

    private async Task<(InitialAccessToken token, string TokenValue)> CreateInitialAccessTokenAsync()
    {
        var (entity, tokenValue) = await _dcrService.CreateInitialAccessTokenAsync(
            "Test Token",
            "admin-id",
            "admin@example.com",
            "Test description",
            DateTime.UtcNow.AddDays(1),
            true,
            10);

        return (entity, tokenValue);
    }

    private async Task<(DynamicClientRegistration dcr, string RegistrationAccessToken, string ClientId)> CreateRegisteredClientAsync()
    {
        var clientId = _dcrService.GenerateClientId();
        var (ratEntity, ratValue) = await _dcrService.CreateRegistrationAccessTokenAsync(clientId);

        var dcr = await _dcrService.CreateDynamicClientRegistrationAsync(
            clientId,
            ratEntity.Id,
            null,
            false,
            "127.0.0.1",
            "Test Browser");

        return (dcr, ratValue, clientId);
    }

    // Async enumerable helpers - local to avoid conflicts with AdminControllerTests
    private static IAsyncEnumerable<T> EmptyAsyncEnumerable<T>()
    {
        return new EmptyAsyncEnumerableImpl<T>();
    }

    private static IAsyncEnumerable<T> ToAsyncEnumerable<T>(IEnumerable<T> source)
    {
        return new AsyncEnumerableWrapper<T>(source);
    }

    private class EmptyAsyncEnumerableImpl<T> : IAsyncEnumerable<T>
    {
        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
            => new EmptyAsyncEnumerator();

        private class EmptyAsyncEnumerator : IAsyncEnumerator<T>
        {
            public T Current => default!;
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
            public ValueTask<bool> MoveNextAsync() => ValueTask.FromResult(false);
        }
    }

    private class AsyncEnumerableWrapper<T> : IAsyncEnumerable<T>
    {
        private readonly IEnumerable<T> _source;

        public AsyncEnumerableWrapper(IEnumerable<T> source) => _source = source;

        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
            => new AsyncEnumeratorWrapper(_source.GetEnumerator());

        private class AsyncEnumeratorWrapper : IAsyncEnumerator<T>
        {
            private readonly IEnumerator<T> _enumerator;

            public AsyncEnumeratorWrapper(IEnumerator<T> enumerator) => _enumerator = enumerator;

            public T Current => _enumerator.Current;

            public ValueTask DisposeAsync()
            {
                _enumerator.Dispose();
                return ValueTask.CompletedTask;
            }

            public ValueTask<bool> MoveNextAsync() => ValueTask.FromResult(_enumerator.MoveNext());
        }
    }
}
