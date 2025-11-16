using Andy.Auth.Providers;
using Andy.Auth.Services;
using Andy.Auth.Tests.Helpers;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Moq;

namespace Andy.Auth.Tests.Services;

public class CurrentUserServiceTests
{
    [Fact]
    public async Task GetUserIdAsync_WithAuthenticatedUser_ShouldReturnUserId()
    {
        // Arrange
        var userId = "test-user-123";
        var principal = TestClaimsPrincipalFactory.CreateAndyAuthPrincipal(userId: userId);

        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var mockHttpContext = new DefaultHttpContext { User = principal };
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(mockHttpContext);

        var mockProvider = new Mock<IAuthProvider>();
        mockProvider.Setup(x => x.GetUserClaimsAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>()))
            .ReturnsAsync(new Models.UserClaims { UserId = userId });

        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        var result = await service.GetUserIdAsync();

        // Assert
        result.Should().Be(userId);
    }

    [Fact]
    public async Task GetUserIdAsync_WithoutHttpContext_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var mockProvider = new Mock<IAuthProvider>();
        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        Func<Task> act = async () => await service.GetUserIdAsync();

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*HttpContext is not available*");
    }

    [Fact]
    public async Task GetUserIdAsync_WithUnauthenticatedUser_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var mockHttpContext = new DefaultHttpContext();
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(mockHttpContext);

        var mockProvider = new Mock<IAuthProvider>();
        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        Func<Task> act = async () => await service.GetUserIdAsync();

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*User is not authenticated*");
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithAuthenticatedUser_ShouldReturnClaims()
    {
        // Arrange
        var userId = "test-user-123";
        var email = "test@example.com";
        var name = "Test User";
        var principal = TestClaimsPrincipalFactory.CreateAndyAuthPrincipal(
            userId: userId,
            email: email,
            name: name
        );

        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var mockHttpContext = new DefaultHttpContext { User = principal };
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(mockHttpContext);

        var expectedClaims = new Andy.Auth.Models.UserClaims
        {
            UserId = userId,
            Email = email,
            Name = name
        };

        var mockProvider = new Mock<IAuthProvider>();
        mockProvider.Setup(x => x.GetUserClaimsAsync(principal))
            .ReturnsAsync(expectedClaims);

        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        var result = await service.GetUserClaimsAsync();

        // Assert
        result.Should().NotBeNull();
        result.UserId.Should().Be(userId);
        result.Email.Should().Be(email);
        result.Name.Should().Be(name);
    }

    [Fact]
    public void IsAuthenticated_WithAuthenticatedUser_ShouldReturnTrue()
    {
        // Arrange
        var principal = TestClaimsPrincipalFactory.CreateAndyAuthPrincipal();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var mockHttpContext = new DefaultHttpContext { User = principal };
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(mockHttpContext);

        var mockProvider = new Mock<IAuthProvider>();
        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        var result = service.IsAuthenticated();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsAuthenticated_WithUnauthenticatedUser_ShouldReturnFalse()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var mockHttpContext = new DefaultHttpContext();
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(mockHttpContext);

        var mockProvider = new Mock<IAuthProvider>();
        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        var result = service.IsAuthenticated();

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsAuthenticated_WithoutHttpContext_ShouldReturnFalse()
    {
        // Arrange
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var mockProvider = new Mock<IAuthProvider>();
        var service = new CurrentUserService(mockHttpContextAccessor.Object, mockProvider.Object);

        // Act
        var result = service.IsAuthenticated();

        // Assert
        result.Should().BeFalse();
    }
}
