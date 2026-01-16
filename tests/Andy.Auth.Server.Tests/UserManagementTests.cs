using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for user management features.
/// Tests the Admin UI endpoints for user creation and role management.
/// </summary>
public class UserManagementTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public UserManagementTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    /// <summary>
    /// Helper to check if response indicates authentication is required.
    /// Can be Unauthorized (401), redirect to login (302/307), or Forbidden (403).
    /// </summary>
    private static bool RequiresAuthentication(HttpStatusCode statusCode)
    {
        return statusCode == HttpStatusCode.Unauthorized ||
               statusCode == HttpStatusCode.Forbidden ||
               statusCode == HttpStatusCode.Redirect ||
               statusCode == HttpStatusCode.Found ||
               statusCode == HttpStatusCode.TemporaryRedirect ||
               statusCode == HttpStatusCode.RedirectKeepVerb;
    }

    [Fact]
    public async Task CreateUser_Get_RequiresAuthentication()
    {
        // Act - Try to access CreateUser without authentication
        var response = await _client.GetAsync("/Admin/CreateUser");

        // Assert - Should require authentication (redirect or 401/403)
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task Users_Get_RequiresAuthentication()
    {
        // Act - Try to access Users list without authentication
        var response = await _client.GetAsync("/Admin/Users");

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task UsersApi_Get_RequiresAuthentication()
    {
        // Act - Try to access API without authentication
        var response = await _client.GetAsync("/api/users");

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task McpUsersApi_List_RequiresAuthentication()
    {
        // Act - Try to access MCP tools without authentication
        var response = await _client.GetAsync("/mcp/tools/users/list");

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task UsersApi_Post_RequiresAuthentication()
    {
        // Arrange
        var createRequest = new
        {
            email = "test@example.com",
            fullName = "Test User",
            password = "TestPass123!",
            isAdmin = false,
            mustChangePassword = true
        };

        var content = new StringContent(
            JsonSerializer.Serialize(createRequest),
            System.Text.Encoding.UTF8,
            "application/json");

        // Act - Try to create user without authentication
        var response = await _client.PostAsync("/api/users", content);

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task McpUsersApi_Create_RequiresAuthentication()
    {
        // Arrange
        var createRequest = new
        {
            email = "test@example.com",
            password = "TestPass123!",
            isAdmin = false
        };

        var content = new StringContent(
            JsonSerializer.Serialize(createRequest),
            System.Text.Encoding.UTF8,
            "application/json");

        // Act - Try to create user via MCP without authentication
        var response = await _client.PostAsync("/mcp/tools/users/create", content);

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task UsersApi_Delete_RequiresAuthentication()
    {
        // Act - Try to delete user without authentication
        var response = await _client.DeleteAsync("/api/users/some-user-id");

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task UsersApi_ChangeRole_RequiresAuthentication()
    {
        // Arrange
        var roleRequest = new { role = "Admin" };
        var content = new StringContent(
            JsonSerializer.Serialize(roleRequest),
            System.Text.Encoding.UTF8,
            "application/json");

        // Act - Try to change role without authentication
        var response = await _client.PostAsync("/api/users/some-user-id/roles", content);

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task UsersApi_Suspend_RequiresAuthentication()
    {
        // Arrange
        var suspendRequest = new { reason = "Test suspension" };
        var content = new StringContent(
            JsonSerializer.Serialize(suspendRequest),
            System.Text.Encoding.UTF8,
            "application/json");

        // Act - Try to suspend user without authentication
        var response = await _client.PostAsync("/api/users/some-user-id/suspend", content);

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }

    [Fact]
    public async Task McpUsersApi_GetUser_RequiresAuthentication()
    {
        // Act - Try to get user via MCP without authentication
        var response = await _client.GetAsync("/mcp/tools/users/some-user-id");

        // Assert - Should require authentication
        Assert.True(RequiresAuthentication(response.StatusCode),
            $"Expected authentication required, got {response.StatusCode}");
    }
}
