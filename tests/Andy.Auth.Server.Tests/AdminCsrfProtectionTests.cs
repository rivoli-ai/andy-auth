using System.Net;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// CSRF-protection regression tests for the destructive admin POST actions
/// flagged in andy-auth#51 (SuspendUser, UnsuspendUser, SetExpiration,
/// DeleteUser, UpdateUserName, ResetPassword, RevokeToken, RevokeUserTokens,
/// RevokeAllTokens).
///
/// AdminController is now decorated with <c>[AutoValidateAntiforgeryToken]</c>,
/// so every unsafe method must reject a request that lacks a valid antiforgery
/// token (HTTP 400) while still succeeding when the real UI supplies the token
/// its Razor forms emit.
///
/// These run against an in-memory host backed by SQLite (via
/// <see cref="EnvironmentWebApplicationFactory"/>) so they never require
/// Postgres. Each test seeds a known admin password through the
/// <c>ADMIN_PASSWORD_DEFAULT</c> env var and drives the real
/// login -> render-form -> POST flow through the HTTP pipeline, which is the
/// only way the antiforgery filter actually executes.
/// </summary>
public class AdminCsrfProtectionTests : IDisposable
{
    // Seeded system admin (DbSeeder.SeedTestUserAsync) — password comes from
    // ADMIN_PASSWORD_DEFAULT, which we pin below.
    private const string AdminEmail = "admin@andy-auth.local";
    private const string AdminPassword = "AdminCsrfTest123!";

    // DbSeeder.TestUserWellKnownId — the seeded "test@andy.local" user, used as
    // a real, existing target so the WITH-token actions redirect (302) instead
    // of 404-ing.
    private const string TargetUserId = "00000000-0000-0000-0000-000000000001";

    private readonly string _dbPath;
    private readonly string? _priorAdminPassword;

    public AdminCsrfProtectionTests()
    {
        _dbPath = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-csrf-tests-" + Guid.NewGuid().ToString("N") + ".sqlite");

        _priorAdminPassword = Environment.GetEnvironmentVariable("ADMIN_PASSWORD_DEFAULT");
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_DEFAULT", AdminPassword);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("ADMIN_PASSWORD_DEFAULT", _priorAdminPassword);
        try
        {
            if (File.Exists(_dbPath))
            {
                File.Delete(_dbPath);
            }
        }
        catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    // The nine destructive endpoints from andy-auth#51 with the minimal form
    // fields each expects (the antiforgery token is added/omitted per test).
    private static IReadOnlyList<(string Name, string Path, Dictionary<string, string> Fields)> DestructiveEndpoints() => new[]
    {
        ("SuspendUser", "/Admin/SuspendUser", new Dictionary<string, string> { ["userId"] = TargetUserId, ["reason"] = "csrf-test" }),
        ("UnsuspendUser", "/Admin/UnsuspendUser", new Dictionary<string, string> { ["userId"] = TargetUserId }),
        ("SetExpiration", "/Admin/SetExpiration", new Dictionary<string, string> { ["userId"] = TargetUserId }),
        ("UpdateUserName", "/Admin/UpdateUserName", new Dictionary<string, string> { ["userId"] = TargetUserId, ["newName"] = "Csrf Test" }),
        ("ResetPassword", "/Admin/ResetPassword", new Dictionary<string, string> { ["userId"] = TargetUserId, ["newPassword"] = "ChangedPass123!" }),
        ("RevokeUserTokens", "/Admin/RevokeUserTokens", new Dictionary<string, string> { ["userId"] = TargetUserId }),
        ("RevokeToken", "/Admin/RevokeToken", new Dictionary<string, string> { ["tokenId"] = "no-such-token" }),
        ("RevokeAllTokens", "/Admin/RevokeAllTokens", new Dictionary<string, string>()),
        // DeleteUser last: it soft-deletes the seeded target. The user is still
        // resolvable afterwards, but keeping it last avoids any ordering doubt.
        ("DeleteUser", "/Admin/DeleteUser", new Dictionary<string, string> { ["userId"] = TargetUserId }),
    };

    [Fact]
    public async Task DestructiveAdminPosts_WithoutAntiforgeryToken_AreRejected()
    {
        using var factory = CreateFactory();
        var client = await LoginAsAdminAsync(factory);

        // Prime the antiforgery cookie exactly as a browser would (it is sent
        // automatically on the POSTs below via the cookie-handling client).
        // The realistic CSRF scenario: the browser still carries the cookie,
        // but the attacker-forged request cannot include the matching token.
        await GetAntiforgeryTokenAsync(client, "/Admin/Users");

        foreach (var (name, path, fields) in DestructiveEndpoints())
        {
            var response = await client.PostAsync(path, new FormUrlEncodedContent(fields));

            response.StatusCode.Should().Be(
                HttpStatusCode.BadRequest,
                because: $"{name} is a destructive action and must reject a POST that lacks a valid antiforgery token");
        }
    }

    [Fact]
    public async Task DestructiveAdminPosts_WithAntiforgeryToken_Succeed()
    {
        using var factory = CreateFactory();
        var client = await LoginAsAdminAsync(factory);

        var token = await GetAntiforgeryTokenAsync(client, "/Admin/Users");

        foreach (var (name, path, fields) in DestructiveEndpoints())
        {
            var withToken = new Dictionary<string, string>(fields)
            {
                ["__RequestVerificationToken"] = token
            };

            var response = await client.PostAsync(path, new FormUrlEncodedContent(withToken));

            // A valid token means the antiforgery filter passes and the action
            // runs — which for these endpoints redirects (302) back to the
            // listing. The critical assertion is that it is NOT a 400.
            response.StatusCode.Should().NotBe(
                HttpStatusCode.BadRequest,
                because: $"{name} must accept a POST that carries a valid antiforgery token");
            response.StatusCode.Should().Be(
                HttpStatusCode.Redirect,
                because: $"{name} should execute and redirect back to the admin listing when the token is valid");
        }
    }

    private EnvironmentWebApplicationFactory CreateFactory() =>
        new EnvironmentWebApplicationFactory(
            environmentName: "Development",
            dbPath: _dbPath,
            issuer: "https://localhost:7088/");

    private static async Task<HttpClient> LoginAsAdminAsync(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // Use https so UseHttpsRedirection() (active in Development) does
            // not answer every GET/POST with a 307 to the https endpoint,
            // which would mask the 302-vs-400 distinction we assert on.
            BaseAddress = new Uri("https://localhost/"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var loginPage = await client.GetAsync("/Account/Login");
        loginPage.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginToken = ExtractAntiforgeryToken(await loginPage.Content.ReadAsStringAsync());
        loginToken.Should().NotBeNullOrEmpty("the login page must render an antiforgery token");

        var loginResponse = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = AdminEmail,
            ["Password"] = AdminPassword,
            ["RememberMe"] = "false",
            ["__RequestVerificationToken"] = loginToken
        }));

        // Successful admin login redirects to the home page (302). If auth
        // failed the controller re-renders the login view (200), which would
        // make the assertions below fail loudly rather than silently.
        loginResponse.StatusCode.Should().Be(
            HttpStatusCode.Redirect,
            "admin login must succeed for the CSRF assertions to be meaningful");

        return client;
    }

    private static async Task<string> GetAntiforgeryTokenAsync(HttpClient client, string path)
    {
        var page = await client.GetAsync(path);
        page.StatusCode.Should().Be(
            HttpStatusCode.OK,
            $"authenticated admin should be able to GET {path} (a redirect means login did not stick)");

        var token = ExtractAntiforgeryToken(await page.Content.ReadAsStringAsync());
        token.Should().NotBeNullOrEmpty($"{path} must render antiforgery-protected forms");
        return token;
    }

    private static string ExtractAntiforgeryToken(string html)
    {
        var match = Regex.Match(
            html,
            @"name=""__RequestVerificationToken""[^>]*value=""([^""]+)""");
        return match.Success ? match.Groups[1].Value : string.Empty;
    }
}
