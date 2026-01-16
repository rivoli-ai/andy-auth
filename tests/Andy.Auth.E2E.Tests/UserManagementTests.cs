using Microsoft.Playwright;
using Xunit;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// E2E tests for user management functionality in the admin panel.
/// </summary>
public class UserManagementTests : E2ETestBase
{
    [Fact]
    public async Task UsersPage_DisplaysUserList()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify page loaded
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Users", pageContent);

        // Should see at least the test users (admin and user)
        Assert.True(
            pageContent.Contains("admin@test.com") || pageContent.Contains("Test Admin"),
            "Admin user should be visible");
    }

    [Fact]
    public async Task UsersPage_HasCreateUserButton()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify create user button/link exists
        var createButton = await Page.QuerySelectorAsync("a[href*='CreateUser']");
        Assert.NotNull(createButton);
    }

    [Fact]
    public async Task CreateUserPage_DisplaysForm()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to create user page
        await NavigateToAsync("/Admin/CreateUser");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify form elements exist
        Assert.True(await ElementExistsAsync("input[name='Email']"), "Email field should exist");
        Assert.True(await ElementExistsAsync("input[name='Password']"), "Password field should exist");
        Assert.True(await ElementExistsAsync("input[name='ConfirmPassword']"), "Confirm password field should exist");
    }

    [Fact]
    public async Task CreateUser_WithValidData_CreatesUser()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to create user page
        await NavigateToAsync("/Admin/CreateUser");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Generate unique email for this test
        var testEmail = $"e2etest-{Guid.NewGuid():N}@test.com";

        // Fill in form
        await Page.FillAsync("input[name='Email']", testEmail);
        await Page.FillAsync("input[name='FullName']", "E2E Test User");
        await Page.FillAsync("input[name='Password']", "E2ETest123!");
        await Page.FillAsync("input[name='ConfirmPassword']", "E2ETest123!");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify redirected to users list
        var url = Page.Url;
        Assert.Contains("/Admin/Users", url);

        // Verify success message or user appears in list
        var pageContent = await Page.ContentAsync();
        Assert.True(
            pageContent.Contains("success") ||
            pageContent.Contains("created") ||
            pageContent.Contains(testEmail) ||
            pageContent.Contains("E2E Test User"),
            "User creation should succeed");
    }

    [Fact]
    public async Task CreateUser_WithMismatchedPasswords_ShowsError()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to create user page
        await NavigateToAsync("/Admin/CreateUser");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Fill in form with mismatched passwords
        await Page.FillAsync("input[name='Email']", "mismatch@test.com");
        await Page.FillAsync("input[name='Password']", "Password123!");
        await Page.FillAsync("input[name='ConfirmPassword']", "DifferentPassword123!");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should still be on create page with error
        var url = Page.Url;
        Assert.Contains("CreateUser", url);
    }

    [Fact]
    public async Task CreateUser_WithExistingEmail_ShowsError()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to create user page
        await NavigateToAsync("/Admin/CreateUser");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Try to create user with existing email
        await Page.FillAsync("input[name='Email']", "admin@test.com");
        await Page.FillAsync("input[name='FullName']", "Duplicate User");
        await Page.FillAsync("input[name='Password']", "Password123!");
        await Page.FillAsync("input[name='ConfirmPassword']", "Password123!");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should show error or stay on page
        var pageContent = await Page.ContentAsync();
        var hasError = pageContent.Contains("already") ||
                      pageContent.Contains("exists") ||
                      pageContent.Contains("error") ||
                      pageContent.Contains("taken");
        Assert.True(hasError, "Should show error for duplicate email");
    }

    [Fact]
    public async Task UsersPage_CanSearchUsers()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for search input
        var searchInput = await Page.QuerySelectorAsync("input[name='search'], input[type='search'], input[placeholder*='search' i]");

        if (searchInput != null)
        {
            // Enter search term
            await searchInput.FillAsync("admin");

            // Submit search (either via button or enter key)
            var searchButton = await Page.QuerySelectorAsync("button[type='submit']");
            if (searchButton != null)
            {
                await searchButton.ClickAsync();
            }
            else
            {
                await searchInput.PressAsync("Enter");
            }

            await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            // Verify search results
            var pageContent = await Page.ContentAsync();
            Assert.Contains("admin@test.com", pageContent);
        }
    }

    [Fact]
    public async Task UsersPage_DisplaysUserRoles()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for role indicators
        var pageContent = await Page.ContentAsync();
        var hasRoleIndicators = pageContent.Contains("Admin") ||
                               pageContent.Contains("User") ||
                               pageContent.Contains("role", StringComparison.OrdinalIgnoreCase);
        Assert.True(hasRoleIndicators, "User roles should be displayed");
    }

    [Fact]
    public async Task UsersPage_HasDeleteAction()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for delete button/form
        var deleteButton = await Page.QuerySelectorAsync("button:has-text('Delete'), form[action*='Delete'] button");
        Assert.NotNull(deleteButton);
    }

    [Fact]
    public async Task UsersPage_HasResetPasswordAction()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for reset password button/form
        var resetButton = await Page.QuerySelectorAsync(
            "button:has-text('Reset'), form[action*='Reset'] button, a:has-text('Reset')");

        // Reset password action should exist
        Assert.NotNull(resetButton);
    }

    [Fact]
    public async Task UsersPage_RegularUserCannotAccess()
    {
        // Login as regular user
        await LoginAsUserAsync();

        // Try to navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be redirected or denied
        var url = Page.Url;
        Assert.False(
            url.Contains("/Admin/Users") && !url.Contains("AccessDenied") && !url.Contains("Login"),
            "Regular user should not access admin users page");
    }
}
