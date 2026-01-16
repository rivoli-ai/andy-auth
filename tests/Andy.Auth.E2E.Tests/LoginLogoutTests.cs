using Microsoft.Playwright;
using Xunit;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// E2E tests for login and logout functionality.
/// </summary>
public class LoginLogoutTests : E2ETestBase
{
    [Fact]
    public async Task LoginPage_DisplaysCorrectly()
    {
        // Navigate to login page
        await NavigateToAsync("/Account/Login");

        // Verify page title
        var title = await Page.TitleAsync();
        Assert.Contains("Login", title, StringComparison.OrdinalIgnoreCase);

        // Verify form elements exist
        Assert.True(await ElementExistsAsync("input[name='Email']"));
        Assert.True(await ElementExistsAsync("input[name='Password']"));
        Assert.True(await ElementExistsAsync("button[type='submit']"));
    }

    [Fact]
    public async Task Login_WithValidCredentials_RedirectsToHome()
    {
        // Navigate to login page
        await NavigateToAsync("/Account/Login");

        // Fill in valid credentials
        await Page.FillAsync("input[name='Email']", "admin@test.com");
        await Page.FillAsync("input[name='Password']", "Admin123!");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify we're redirected (not on login page anymore)
        var url = Page.Url;
        Assert.DoesNotContain("/Account/Login", url);
    }

    [Fact]
    public async Task Login_WithInvalidCredentials_ShowsError()
    {
        // Navigate to login page
        await NavigateToAsync("/Account/Login");

        // Fill in invalid credentials
        await Page.FillAsync("input[name='Email']", "admin@test.com");
        await Page.FillAsync("input[name='Password']", "WrongPassword!");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify we're still on login page
        var url = Page.Url;
        Assert.Contains("/Account/Login", url);

        // Verify error message is displayed
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Invalid login attempt", pageContent);
    }

    [Fact]
    public async Task Login_WithEmptyFields_ShowsValidationErrors()
    {
        // Navigate to login page
        await NavigateToAsync("/Account/Login");

        // Submit without filling in any fields
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify we're still on login page
        var url = Page.Url;
        Assert.Contains("/Account/Login", url);
    }

    [Fact]
    public async Task Logout_RedirectsToHome()
    {
        // First login
        await LoginAsAdminAsync();

        // Then logout
        await LogoutAsync();

        // Verify we're on home page or login page
        var url = Page.Url;
        Assert.True(url.EndsWith("/") || url.Contains("/Home") || url.Contains("/Account/Login"),
            $"Expected to be redirected to home or login, but URL was: {url}");
    }

    [Fact]
    public async Task Login_AsAdmin_CanAccessAdminDashboard()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to admin dashboard
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify we can access admin page (not redirected to login/access denied)
        var url = Page.Url;
        Assert.Contains("/Admin", url);

        // Verify admin content is displayed
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Admin", pageContent);
    }

    [Fact]
    public async Task Login_AsRegularUser_CannotAccessAdminDashboard()
    {
        // Login as regular user
        await LoginAsUserAsync();

        // Try to navigate to admin dashboard
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify we're redirected (access denied or login)
        var url = Page.Url;
        var hasAccess = url.Contains("/Admin") && !url.Contains("AccessDenied") && !url.Contains("Login");
        Assert.False(hasAccess, "Regular user should not have access to admin dashboard");
    }

    [Fact]
    public async Task Login_RememberMe_SetsAuthenticationCookie()
    {
        // Navigate to login page
        await NavigateToAsync("/Account/Login");

        // Fill in credentials with remember me checked
        await Page.FillAsync("input[name='Email']", "admin@test.com");
        await Page.FillAsync("input[name='Password']", "Admin123!");

        // Check remember me if it exists
        var rememberMeCheckbox = await Page.QuerySelectorAsync("input[name='RememberMe']");
        if (rememberMeCheckbox != null)
        {
            await rememberMeCheckbox.CheckAsync();
        }

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Get cookies
        var cookies = await Context.CookiesAsync();

        // Verify authentication cookie exists
        var authCookie = cookies.FirstOrDefault(c => c.Name.Contains("Identity") || c.Name.Contains("Auth"));
        Assert.NotNull(authCookie);
    }
}
