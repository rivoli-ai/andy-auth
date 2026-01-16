using Microsoft.Playwright;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// Base class for E2E tests using Playwright.
/// Manages browser lifecycle and provides common test utilities.
/// </summary>
public abstract class E2ETestBase : IAsyncLifetime
{
    protected E2ETestServer Server { get; private set; } = null!;
    protected IPlaywright Playwright { get; private set; } = null!;
    protected IBrowser Browser { get; private set; } = null!;
    protected IBrowserContext Context { get; private set; } = null!;
    protected IPage Page { get; private set; } = null!;
    protected string BaseUrl { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        // Create and start test server
        Server = new E2ETestServer();
        await Server.StartAsync();
        BaseUrl = Server.ServerAddress;

        // Initialize Playwright
        Playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        Browser = await Playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });

        Context = await Browser.NewContextAsync(new BrowserNewContextOptions
        {
            BaseURL = BaseUrl,
            IgnoreHTTPSErrors = true
        });

        Page = await Context.NewPageAsync();
    }

    public async Task DisposeAsync()
    {
        if (Page != null)
            await Page.CloseAsync();

        if (Context != null)
            await Context.CloseAsync();

        if (Browser != null)
            await Browser.CloseAsync();

        Playwright?.Dispose();

        if (Server != null)
            await Server.DisposeAsync();
    }

    /// <summary>
    /// Navigate to a page relative to the base URL.
    /// </summary>
    protected async Task NavigateToAsync(string path)
    {
        var response = await Page.GotoAsync($"{BaseUrl}{path}");
        if (response == null)
            throw new Exception($"Failed to navigate to {path}");
    }

    /// <summary>
    /// Log in as the test admin user.
    /// </summary>
    protected async Task LoginAsAdminAsync()
    {
        await LoginAsync("admin@test.com", "Admin123!");
    }

    /// <summary>
    /// Log in as the test regular user.
    /// </summary>
    protected async Task LoginAsUserAsync()
    {
        await LoginAsync("user@test.com", "User123!");
    }

    /// <summary>
    /// Log in with the specified credentials.
    /// </summary>
    protected async Task LoginAsync(string email, string password)
    {
        await NavigateToAsync("/Account/Login");

        // Fill in login form
        await Page.FillAsync("input[name='Email']", email);
        await Page.FillAsync("input[name='Password']", password);

        // Submit form
        await Page.ClickAsync("button[type='submit']");

        // Wait for navigation to complete
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
    }

    /// <summary>
    /// Log out the current user.
    /// </summary>
    protected async Task LogoutAsync()
    {
        await NavigateToAsync("/Account/Logout");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
    }

    /// <summary>
    /// Wait for an element to be visible and return its text content.
    /// </summary>
    protected async Task<string> GetTextContentAsync(string selector)
    {
        var element = await Page.WaitForSelectorAsync(selector);
        return await element!.TextContentAsync() ?? string.Empty;
    }

    /// <summary>
    /// Check if an element exists on the page.
    /// </summary>
    protected async Task<bool> ElementExistsAsync(string selector)
    {
        var element = await Page.QuerySelectorAsync(selector);
        return element != null;
    }

    /// <summary>
    /// Get the value of a data attribute on an element.
    /// </summary>
    protected async Task<string?> GetDataAttributeAsync(string selector, string attributeName)
    {
        var element = await Page.QuerySelectorAsync(selector);
        if (element == null) return null;
        return await element.GetAttributeAsync($"data-{attributeName}");
    }

    /// <summary>
    /// Wait for date formatting JavaScript to complete.
    /// </summary>
    protected async Task WaitForDateFormattingAsync()
    {
        await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
        await Task.Delay(200); // Give JS time to process
    }
}
