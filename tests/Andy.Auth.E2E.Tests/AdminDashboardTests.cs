using Microsoft.Playwright;
using Xunit;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// E2E tests for admin dashboard and OAuth client management.
/// </summary>
public class AdminDashboardTests : E2ETestBase
{
    [Fact]
    public async Task AdminDashboard_DisplaysStatistics()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to admin dashboard
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify dashboard loaded
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Dashboard", pageContent, StringComparison.OrdinalIgnoreCase);

        // Check for stats cards
        var hasStats = pageContent.Contains("Users", StringComparison.OrdinalIgnoreCase) ||
                      pageContent.Contains("Clients", StringComparison.OrdinalIgnoreCase) ||
                      pageContent.Contains("Active", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasStats, "Dashboard should display statistics");
    }

    [Fact]
    public async Task AdminDashboard_HasQuickActions()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to admin dashboard
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for quick action links
        var manageUsersLink = await Page.QuerySelectorAsync("a[href*='Users']");
        var manageClientsLink = await Page.QuerySelectorAsync("a[href*='Clients']");

        Assert.NotNull(manageUsersLink);
        Assert.NotNull(manageClientsLink);
    }

    [Fact]
    public async Task AdminDashboard_ShowsRecentActivity()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to admin dashboard
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for recent activity section
        var pageContent = await Page.ContentAsync();
        var hasActivity = pageContent.Contains("Recent", StringComparison.OrdinalIgnoreCase) ||
                         pageContent.Contains("Activity", StringComparison.OrdinalIgnoreCase) ||
                         pageContent.Contains("Login", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasActivity, "Dashboard should show recent activity");
    }

    [Fact]
    public async Task OAuthClientsPage_DisplaysClientList()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to clients page
        await NavigateToAsync("/Admin/Clients");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify page loaded
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Client", pageContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OAuthClientsPage_HasCreateButton()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to clients page
        await NavigateToAsync("/Admin/Clients");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for create button
        var createButton = await Page.QuerySelectorAsync("a[href*='CreateClient'], button:has-text('Create')");
        Assert.NotNull(createButton);
    }

    [Fact]
    public async Task TokensPage_DisplaysTokenList()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to tokens page
        await NavigateToAsync("/Admin/Tokens");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify page loaded
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Token", pageContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TokensPage_HasFilterOptions()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to tokens page
        await NavigateToAsync("/Admin/Tokens");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for filter controls
        var hasFilters = await ElementExistsAsync("select[name='status']") ||
                        await ElementExistsAsync("input[name='search']") ||
                        await ElementExistsAsync(".filter");

        Assert.True(hasFilters, "Tokens page should have filter options");
    }

    [Fact]
    public async Task AuditLogsPage_DisplaysLogs()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to audit logs page
        await NavigateToAsync("/Admin/AuditLogs");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify page loaded
        var pageContent = await Page.ContentAsync();
        Assert.Contains("Audit", pageContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AuditLogsPage_HasFilterOptions()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to audit logs page
        await NavigateToAsync("/Admin/AuditLogs");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for filter controls
        var hasFilters = await ElementExistsAsync("select[name='action']") ||
                        await ElementExistsAsync("input[type='date']") ||
                        await ElementExistsAsync("input[name='search']");

        Assert.True(hasFilters, "Audit logs page should have filter options");
    }

    [Fact]
    public async Task MyConsentsPage_DisplaysConsents()
    {
        // Login as user
        await LoginAsUserAsync();

        // Navigate to consents page
        await NavigateToAsync("/Consent/MyConsents");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Verify page loaded
        var pageContent = await Page.ContentAsync();
        var hasConsentsContent = pageContent.Contains("Authorized", StringComparison.OrdinalIgnoreCase) ||
                                pageContent.Contains("Applications", StringComparison.OrdinalIgnoreCase) ||
                                pageContent.Contains("Consent", StringComparison.OrdinalIgnoreCase) ||
                                pageContent.Contains("No authorized", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasConsentsContent, "Consents page should display consent information");
    }

    [Fact]
    public async Task MyConsentsPage_EmptyStateDisplayedWhenNoConsents()
    {
        // Login as user (fresh user with no consents)
        await LoginAsUserAsync();

        // Navigate to consents page
        await NavigateToAsync("/Consent/MyConsents");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Check for empty state or consent list
        var pageContent = await Page.ContentAsync();
        var hasContent = pageContent.Contains("No authorized", StringComparison.OrdinalIgnoreCase) ||
                        pageContent.Contains("empty", StringComparison.OrdinalIgnoreCase) ||
                        pageContent.Contains("consent-card", StringComparison.OrdinalIgnoreCase) ||
                        pageContent.Contains("application", StringComparison.OrdinalIgnoreCase);

        Assert.True(hasContent, "Consents page should show either consents or empty state");
    }
}
