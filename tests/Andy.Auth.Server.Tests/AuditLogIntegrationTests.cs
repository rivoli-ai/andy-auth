using System.Net;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Integration tests for the Audit Log functionality.
/// Verifies that user actions are properly logged to the AuditLogs table.
///
/// These run fully hermetically against the isolated SQLite database that
/// <see cref="CustomWebApplicationFactory"/> provisions and the deterministic
/// admin user it seeds (<see cref="CustomWebApplicationFactory.AdminEmail"/>).
/// The AuditLogs table always exists (EnsureCreated builds the whole model),
/// so there is no "table not seeded" branch to skip.
/// </summary>
public class AuditLogIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;

    public AuditLogIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// A client that persists cookies across requests (so the anti-forgery
    /// cookie from the login GET is presented on the POST) and does not
    /// auto-follow redirects (so a successful login surfaces as its 302).
    /// The base address is https so the app's HTTPS-redirection middleware
    /// doesn't 307 every request (which would otherwise be swallowed as a
    /// redirect instead of the response we assert on).
    /// </summary>
    private HttpClient CreateCookieClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true,
            BaseAddress = new Uri("https://localhost"),
        });

    /// <summary>
    /// Drives the Razor login form: GETs the page, extracts the anti-forgery
    /// token, and POSTs the credentials on the same cookie-bearing client.
    /// Returns the POST response (302 on success, 200 with the re-rendered
    /// form on failure).
    /// </summary>
    private static async Task<HttpResponseMessage> LoginAsync(
        HttpClient client, string email, string password)
    {
        var loginPage = await client.GetAsync("/Account/Login");
        loginPage.EnsureSuccessStatusCode();
        var html = await loginPage.Content.ReadAsStringAsync();

        var tokenMatch = Regex.Match(
            html,
            @"<input[^>]*name=""__RequestVerificationToken""[^>]*value=""([^""]+)""");
        Assert.True(tokenMatch.Success,
            "Login page must render an anti-forgery token hidden input.");

        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "Email", email },
            { "Password", password },
            { "RememberMe", "false" },
            { "__RequestVerificationToken", tokenMatch.Groups[1].Value },
        });

        return await client.PostAsync("/Account/Login", form);
    }

    [Fact]
    public async Task SuccessfulLogin_CreatesUserLoginAuditLog()
    {
        var client = CreateCookieClient();

        var loginResponse = await LoginAsync(
            client, CustomWebApplicationFactory.AdminEmail, CustomWebApplicationFactory.AdminPassword);

        // A successful sign-in redirects away from the login form.
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var recentLoginLog = await dbContext.AuditLogs
            .Where(l => l.Action == "UserLogin"
                        && l.PerformedByEmail == CustomWebApplicationFactory.AdminEmail)
            .OrderByDescending(l => l.PerformedAt)
            .FirstOrDefaultAsync();

        Assert.NotNull(recentLoginLog);
        Assert.Equal("UserLogin", recentLoginLog!.Action);
        Assert.Equal(CustomWebApplicationFactory.AdminEmail, recentLoginLog.PerformedByEmail);
        Assert.Contains("Successful login", recentLoginLog.Details);
    }

    [Fact]
    public async Task FailedLogin_CreatesUserLoginFailedAuditLog()
    {
        int existingFailedLoginCount;
        using (var scopeBefore = _factory.Services.CreateScope())
        {
            var dbContextBefore = scopeBefore.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            existingFailedLoginCount = await dbContextBefore.AuditLogs
                .Where(l => l.Action == "UserLoginFailed"
                            && l.PerformedByEmail == CustomWebApplicationFactory.AdminEmail)
                .CountAsync();
        }

        var client = CreateCookieClient();

        // A real, seeded user with the wrong password — the controller only
        // records UserLoginFailed for users that actually exist.
        var loginResponse = await LoginAsync(
            client, CustomWebApplicationFactory.AdminEmail, "WrongPassword123!");

        // Failed login re-renders the form (200), it does not redirect.
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var newFailedLoginCount = await dbContext.AuditLogs
            .Where(l => l.Action == "UserLoginFailed"
                        && l.PerformedByEmail == CustomWebApplicationFactory.AdminEmail)
            .CountAsync();

        Assert.True(newFailedLoginCount > existingFailedLoginCount,
            "A new UserLoginFailed audit log entry should have been created");
    }

    [Fact]
    public async Task AuditLogsPage_DisplaysLogs()
    {
        var client = CreateCookieClient();

        var loginResponse = await LoginAsync(
            client, CustomWebApplicationFactory.AdminEmail, CustomWebApplicationFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);

        // Act - Access the admin-only Audit Logs page with the authenticated
        // session cookie the login established.
        var auditLogsResponse = await client.GetAsync("/Admin/AuditLogs");

        // Assert
        Assert.Equal(HttpStatusCode.OK, auditLogsResponse.StatusCode);
        var auditLogsContent = await auditLogsResponse.Content.ReadAsStringAsync();
        Assert.Contains("Audit Logs", auditLogsContent);
    }

    [Fact]
    public async Task AuditLog_ContainsExpectedProperties()
    {
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        // Create a test audit log if none exist.
        if (!await dbContext.AuditLogs.AnyAsync())
        {
            dbContext.AuditLogs.Add(new AuditLog
            {
                Action = "TestAction",
                PerformedById = "test-user-id",
                PerformedByEmail = "test@example.com",
                TargetUserId = "target-user-id",
                TargetUserEmail = "target@example.com",
                Details = "Test audit log entry",
                PerformedAt = DateTime.UtcNow,
                IpAddress = "127.0.0.1"
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var auditLog = await dbContext.AuditLogs.FirstAsync();

        // Assert
        Assert.NotNull(auditLog.Action);
        Assert.NotNull(auditLog.PerformedById);
        Assert.NotNull(auditLog.PerformedByEmail);
        Assert.NotEqual(default, auditLog.PerformedAt);
    }
}
