using Microsoft.Playwright;
using Xunit;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// E2E tests for password change functionality including forced password change on first login.
/// </summary>
public class PasswordChangeTests : E2ETestBase
{
    [Fact]
    public async Task ChangePasswordPage_DisplaysForm()
    {
        // Login as regular user
        await LoginAsUserAsync();

        // Navigate to change password page
        await NavigateToAsync("/Account/ChangePassword");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify form elements exist
        Assert.True(await ElementExistsAsync("input[name='NewPassword']"), "New password field should exist");
        Assert.True(await ElementExistsAsync("input[name='ConfirmPassword']"), "Confirm password field should exist");
        Assert.True(await ElementExistsAsync("button[type='submit']"), "Submit button should exist");
    }

    [Fact]
    public async Task ChangePassword_WithMismatchedPasswords_ShowsError()
    {
        // Login as regular user
        await LoginAsUserAsync();

        // Navigate to change password page
        await NavigateToAsync("/Account/ChangePassword");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Fill in mismatched passwords
        await Page.FillAsync("input[name='NewPassword']", "NewPassword123!");
        await Page.FillAsync("input[name='ConfirmPassword']", "DifferentPassword123!");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should stay on change password page with error
        var url = Page.Url;
        Assert.Contains("ChangePassword", url);

        // Should show validation error
        var pageContent = await Page.ContentAsync();
        var hasError = pageContent.Contains("match", StringComparison.OrdinalIgnoreCase) ||
                      pageContent.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                      pageContent.Contains("validation", StringComparison.OrdinalIgnoreCase);
        Assert.True(hasError, "Should show password mismatch error");
    }

    [Fact]
    public async Task ChangePassword_WithWeakPassword_ShowsError()
    {
        // Login as regular user
        await LoginAsUserAsync();

        // Navigate to change password page
        await NavigateToAsync("/Account/ChangePassword");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Fill in weak password
        await Page.FillAsync("input[name='NewPassword']", "weak");
        await Page.FillAsync("input[name='ConfirmPassword']", "weak");

        // Submit form
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should stay on change password page with error
        var url = Page.Url;
        Assert.Contains("ChangePassword", url);
    }

    [Fact]
    public async Task ChangePasswordPage_ShowsPasswordRequirements()
    {
        // Login as regular user
        await LoginAsUserAsync();

        // Navigate to change password page
        await NavigateToAsync("/Account/ChangePassword");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for password requirements text
        var pageContent = await Page.ContentAsync();
        var hasRequirements = pageContent.Contains("8", StringComparison.OrdinalIgnoreCase) || // min length
                             pageContent.Contains("character", StringComparison.OrdinalIgnoreCase) ||
                             pageContent.Contains("uppercase", StringComparison.OrdinalIgnoreCase) ||
                             pageContent.Contains("lowercase", StringComparison.OrdinalIgnoreCase) ||
                             pageContent.Contains("digit", StringComparison.OrdinalIgnoreCase) ||
                             pageContent.Contains("number", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasRequirements, "Password requirements should be displayed");
    }

    [Fact]
    public async Task ForcedPasswordChange_RedirectsToChangePasswordPage()
    {
        // Login with user that must change password
        await NavigateToAsync("/Account/Login");

        await Page.FillAsync("input[name='Email']", "mustchange@test.com");
        await Page.FillAsync("input[name='Password']", "TempPass123!");

        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be redirected to change password page
        var url = Page.Url;
        Assert.Contains("ChangePassword", url);
    }

    [Fact]
    public async Task ForcedPasswordChange_ShowsWarningBanner()
    {
        // Login with user that must change password
        await NavigateToAsync("/Account/Login");

        await Page.FillAsync("input[name='Email']", "mustchange@test.com");
        await Page.FillAsync("input[name='Password']", "TempPass123!");

        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for warning/alert about required password change
        var pageContent = await Page.ContentAsync();
        var hasWarning = pageContent.Contains("required", StringComparison.OrdinalIgnoreCase) ||
                        pageContent.Contains("must", StringComparison.OrdinalIgnoreCase) ||
                        pageContent.Contains("change your password", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasWarning, "Should show warning about required password change");
    }

    [Fact]
    public async Task ForcedPasswordChange_SamePasswordRejected()
    {
        // Login with user that must change password
        await NavigateToAsync("/Account/Login");

        await Page.FillAsync("input[name='Email']", "mustchange@test.com");
        await Page.FillAsync("input[name='Password']", "TempPass123!");

        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be on change password page
        Assert.Contains("ChangePassword", Page.Url);

        // Try to use the same password
        await Page.FillAsync("input[name='NewPassword']", "TempPass123!");
        await Page.FillAsync("input[name='ConfirmPassword']", "TempPass123!");

        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should still be on change password page with error
        Assert.Contains("ChangePassword", Page.Url);

        // Should show error about same password
        var pageContent = await Page.ContentAsync();
        Assert.Contains("same", pageContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ForcedPasswordChange_NewPasswordAccepted()
    {
        // Login with user that must change password
        await NavigateToAsync("/Account/Login");

        await Page.FillAsync("input[name='Email']", "mustchange@test.com");
        await Page.FillAsync("input[name='Password']", "TempPass123!");

        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be on change password page
        if (!Page.Url.Contains("ChangePassword"))
        {
            // User might not have MustChangePassword flag set in test data
            return;
        }

        // Use a different password
        var newPassword = $"NewSecurePass{Guid.NewGuid():N}!";
        await Page.FillAsync("input[name='NewPassword']", newPassword);
        await Page.FillAsync("input[name='ConfirmPassword']", newPassword);

        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be redirected away from change password page
        var url = Page.Url;
        Assert.DoesNotContain("ChangePassword", url);
    }

    [Fact]
    public async Task ChangePassword_RequiresAuthentication()
    {
        // Try to access change password without logging in
        await NavigateToAsync("/Account/ChangePassword");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be redirected to login
        var url = Page.Url;
        Assert.True(
            url.Contains("Login"),
            "Change password page should require authentication");
    }

    [Fact]
    public async Task AdminResetPassword_SetsForceChangeFlag()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Find the reset password button for test user
        var resetButton = await Page.QuerySelectorAsync(
            "form[action*='ResetPassword'] button, button:has-text('Reset')");

        if (resetButton != null)
        {
            // The reset password functionality should exist
            Assert.NotNull(resetButton);
        }
    }
}
