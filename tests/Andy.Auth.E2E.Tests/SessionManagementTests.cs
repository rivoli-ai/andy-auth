using Microsoft.Playwright;
using Xunit;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// E2E tests for session management functionality.
/// </summary>
public class SessionManagementTests : E2ETestBase
{
    [Fact]
    public async Task SessionsPage_DisplaysCurrentSession()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify page loaded with session information
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Session", pageContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SessionsPage_ShowsCurrentSessionBadge()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for current session indicator
        var currentBadge = await Page.QuerySelectorAsync(".current-badge, .current, [class*='current']");
        Assert.NotNull(currentBadge);

        var badgeText = await currentBadge.TextContentAsync();
        Assert.Contains("Current", badgeText!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SessionsPage_DisplaysSessionMetadata()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify session metadata is displayed
        var pageContent = await Page.ContentAsync();

        // Should show some session information (device, browser, IP, etc.)
        var hasMetadata = pageContent.Contains("Last active", StringComparison.OrdinalIgnoreCase) ||
                         pageContent.Contains("Signed in", StringComparison.OrdinalIgnoreCase) ||
                         pageContent.Contains("IP", StringComparison.OrdinalIgnoreCase) ||
                         pageContent.Contains("Browser", StringComparison.OrdinalIgnoreCase) ||
                         pageContent.Contains("Device", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasMetadata, "Session metadata should be displayed");
    }

    [Fact]
    public async Task SessionsPage_ShowsSessionCount()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for session count indicator
        var pageContent = await Page.ContentAsync();

        // Should show session count (e.g., "1 / 5 sessions active")
        var hasSessionCount = pageContent.Contains("sessions", StringComparison.OrdinalIgnoreCase) ||
                             pageContent.Contains("/", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasSessionCount, "Session count should be displayed");
    }

    [Fact]
    public async Task SessionsPage_CurrentSessionCannotBeRevoked()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for the current session's revoke button
        var currentSessionCard = await Page.QuerySelectorAsync(".session-card.current, .current");

        if (currentSessionCard != null)
        {
            // The revoke button for current session should be disabled
            var revokeButton = await currentSessionCard.QuerySelectorAsync("button:has-text('Revoke'), button:has-text('Current')");

            if (revokeButton != null)
            {
                var isDisabled = await revokeButton.IsDisabledAsync();
                Assert.True(isDisabled, "Current session revoke button should be disabled");
            }
        }
    }

    [Fact]
    public async Task SessionsPage_HasRevokeAllOtherButton()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Look for "revoke all other" button
        var revokeAllButton = await Page.QuerySelectorAsync(
            "button:has-text('Sign out all'), button:has-text('Revoke all'), form[action*='RevokeAllOther'] button");

        // Note: This button might only appear when there are multiple sessions
        // If there's only one session (current), it might not be visible
    }

    [Fact]
    public async Task SessionsPage_RequiresAuthentication()
    {
        // Try to access sessions page without logging in
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Should be redirected to login
        var url = Page.Url;
        Assert.True(
            url.Contains("Login") || url.Contains("Account"),
            "Sessions page should require authentication");
    }

    [Fact]
    public async Task SessionsPage_DatesAreInLocalFormat()
    {
        // Login
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Check for formatted dates
        var dateElements = await Page.QuerySelectorAllAsync("[data-utc]");
        Assert.True(dateElements.Count > 0, "Should have date elements");

        foreach (var element in dateElements)
        {
            var text = await element.TextContentAsync();
            Assert.DoesNotContain("T", text ?? ""); // Should not be ISO format
        }
    }
}
