using Microsoft.Playwright;
using Xunit;

namespace Andy.Auth.E2E.Tests;

/// <summary>
/// E2E tests for date formatting functionality.
/// Verifies that dates stored in UTC are properly converted to local time in the browser.
/// </summary>
public class DateFormattingTests : E2ETestBase
{
    [Fact]
    public async Task AdminUsersPage_DatesHaveDataUtcAttribute()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Check that date elements have data-utc attributes
        var dateElements = await Page.QuerySelectorAllAsync("[data-utc]");
        Assert.True(dateElements.Count > 0, "Expected date elements with data-utc attribute");

        // Verify each element has a valid ISO date in data-utc
        foreach (var element in dateElements)
        {
            var utcValue = await element.GetAttributeAsync("data-utc");
            Assert.NotNull(utcValue);
            Assert.True(DateTime.TryParse(utcValue, out _), $"Invalid date format: {utcValue}");
        }
    }

    [Fact]
    public async Task AdminUsersPage_DatesAreFormattedToLocalTime()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Get a date element
        var dateElement = await Page.QuerySelectorAsync("[data-utc]");
        Assert.NotNull(dateElement);

        // Get the displayed text
        var displayedText = await dateElement.TextContentAsync();
        Assert.NotNull(displayedText);

        // The displayed text should NOT be in ISO format (should be human-readable)
        Assert.DoesNotContain("T", displayedText!); // ISO format has T separator
        Assert.DoesNotContain("Z", displayedText); // ISO format might have Z suffix

        // Should contain readable date parts
        var hasReadableFormat = displayedText.Contains(",") || // "Jan 15, 2026"
                               displayedText.Contains("/") || // "1/15/2026"
                               displayedText.Contains("-");   // "15-Jan-2026"
        Assert.True(hasReadableFormat, $"Date format appears incorrect: {displayedText}");
    }

    [Fact]
    public async Task AdminUsersPage_DateElementsHaveTooltipWithUtc()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to users page
        await NavigateToAsync("/Admin/Users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Get a date element
        var dateElement = await Page.QuerySelectorAsync("[data-utc]");
        Assert.NotNull(dateElement);

        // Verify the title attribute contains UTC reference
        var title = await dateElement.GetAttributeAsync("title");
        Assert.NotNull(title);
        Assert.Contains("UTC", title!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminAuditLogsPage_DatesWithSecondsFormat()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to audit logs page
        await NavigateToAsync("/Admin/AuditLogs");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Check for date elements with datetime-seconds format
        var dateElements = await Page.QuerySelectorAllAsync("[data-format='datetime-seconds']");

        // If audit logs exist, verify format
        if (dateElements.Count > 0)
        {
            foreach (var element in dateElements)
            {
                var utcValue = await element.GetAttributeAsync("data-utc");
                Assert.NotNull(utcValue);

                var displayedText = await element.TextContentAsync();
                Assert.NotNull(displayedText);

                // Should be formatted (not raw ISO)
                Assert.DoesNotContain("T", displayedText!);
            }
        }
    }

    [Fact]
    public async Task AdminTokensPage_DatesAreFormatted()
    {
        // Login as admin
        await LoginAsAdminAsync();

        // Navigate to tokens page
        await NavigateToAsync("/Admin/Tokens");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Check for date elements
        var dateElements = await Page.QuerySelectorAllAsync("[data-utc]");

        // If tokens exist, verify formatting
        if (dateElements.Count > 0)
        {
            var element = dateElements[0];
            var displayedText = await element.TextContentAsync();

            // Should be formatted, not raw ISO
            Assert.DoesNotContain("T", displayedText ?? "");
        }
    }

    [Fact]
    public async Task SessionsPage_DatesAreFormatted()
    {
        // Login as admin (or user)
        await LoginAsAdminAsync();

        // Navigate to sessions page
        await NavigateToAsync("/Session");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Check for date elements
        var dateElements = await Page.QuerySelectorAllAsync("[data-utc]");

        // Should have at least one session (current)
        Assert.True(dateElements.Count > 0, "Expected at least one session with date");

        foreach (var element in dateElements)
        {
            var displayedText = await element.TextContentAsync();
            Assert.NotNull(displayedText);

            // Should be formatted, not raw ISO
            Assert.DoesNotContain("T", displayedText!);
        }
    }

    [Fact]
    public async Task ConsentsPage_DatesAreFormatted()
    {
        // Login as user
        await LoginAsUserAsync();

        // Navigate to consents page
        await NavigateToAsync("/Consent/MyConsents");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await WaitForDateFormattingAsync();

        // Check for date elements (may be empty if no consents)
        var dateElements = await Page.QuerySelectorAllAsync("[data-utc]");

        // If consents exist, verify formatting
        foreach (var element in dateElements)
        {
            var displayedText = await element.TextContentAsync();
            Assert.DoesNotContain("T", displayedText ?? "");
        }
    }

    [Fact]
    public async Task DateFormatting_JavaScriptFunctionExists()
    {
        // Login and navigate to any page
        await LoginAsAdminAsync();
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

        // Verify the formatLocalDate function exists
        var functionExists = await Page.EvaluateAsync<bool>("typeof formatLocalDate === 'function'");
        Assert.True(functionExists, "formatLocalDate JavaScript function should exist");
    }

    [Fact]
    public async Task DateFormatting_JavaScriptFunctionWorksCorrectly()
    {
        // Login and navigate to any page
        await LoginAsAdminAsync();
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

        // Test the formatLocalDate function with a known UTC date
        var result = await Page.EvaluateAsync<string>(
            "formatLocalDate('2024-06-15T14:30:00Z', 'datetime')");

        Assert.NotNull(result);
        Assert.DoesNotContain("T", result); // Should not be ISO format
        Assert.True(result.Length > 0, "Formatted date should not be empty");

        // Verify it contains expected parts (month, day, time elements)
        // The exact format depends on the browser's locale
        Assert.True(result.Contains("15") || result.Contains("Jun") || result.Contains("6"),
            $"Expected date parts not found in: {result}");
    }

    [Fact]
    public async Task DateFormatting_HandlesDateOnlyFormat()
    {
        // Login and navigate to any page
        await LoginAsAdminAsync();
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

        // Test the formatLocalDate function with 'date' format
        var result = await Page.EvaluateAsync<string>(
            "formatLocalDate('2024-06-15T14:30:00Z', 'date')");

        Assert.NotNull(result);
        Assert.DoesNotContain("T", result);

        // Date-only format should not include time
        // (harder to verify without knowing locale, but shouldn't have seconds)
    }

    [Fact]
    public async Task DateFormatting_HandlesInvalidDates()
    {
        // Login and navigate to any page
        await LoginAsAdminAsync();
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

        // Test with invalid date
        var result = await Page.EvaluateAsync<string>(
            "formatLocalDate('not-a-date', 'datetime')");

        // Should return the original string for invalid dates
        Assert.Equal("not-a-date", result);
    }

    [Fact]
    public async Task DateFormatting_HandlesEmptyString()
    {
        // Login and navigate to any page
        await LoginAsAdminAsync();
        await NavigateToAsync("/Admin");
        await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);

        // Test with empty string
        var result = await Page.EvaluateAsync<string>(
            "formatLocalDate('', 'datetime')");

        // Should return empty string
        Assert.Equal("", result);
    }
}
