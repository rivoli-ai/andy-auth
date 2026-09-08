using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Server.Tests;

public sealed class AdminAccessIntegrationTests : IDisposable
{
    private readonly string? prior = Environment.GetEnvironmentVariable("AdminAccess__EnforceInLocal");
    public AdminAccessIntegrationTests() => Environment.SetEnvironmentVariable("AdminAccess__EnforceInLocal", "true");
    public void Dispose() => Environment.SetEnvironmentVariable("AdminAccess__EnforceInLocal", prior);
    private static HttpClient Browser(WebApplicationFactory<Program> factory) => factory.CreateClient(new WebApplicationFactoryClientOptions
        { BaseAddress = new Uri("https://localhost"), HandleCookies = true, AllowAutoRedirect = false });
    private static string Csrf(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(match.Success);
        return match.Groups[1].Value;
    }
    private static async Task<string> EnableMfa(WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = (await users.FindByEmailAsync(CustomWebApplicationFactory.AdminEmail))!;
        Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
        Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        return (await users.GetAuthenticatorKeyAsync(user))!;
    }
    private static async Task Login(HttpClient browser, string? key = null)
    {
        var csrf = Csrf(await browser.GetStringAsync("/Account/Login"));
        using var login = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = CustomWebApplicationFactory.AdminEmail, ["Password"] = CustomWebApplicationFactory.AdminPassword,
            ["__RequestVerificationToken"] = csrf
        }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        if (key == null) return;
        Assert.Contains("LoginWith2fa", login.Headers.Location!.OriginalString);
        var mfaCsrf = Csrf(await browser.GetStringAsync(login.Headers.Location));
        using var mfa = await browser.PostAsync("/Account/LoginWith2fa", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["TwoFactorCode"] = Code(key), ["__RequestVerificationToken"] = mfaCsrf }));
        Assert.Equal(HttpStatusCode.Redirect, mfa.StatusCode);
    }
    private static async Task<HttpResponseMessage> StepUp(HttpClient browser, string key, string password = CustomWebApplicationFactory.AdminPassword,
        string returnUrl = "/Admin/Users")
    {
        var csrf = Csrf(await browser.GetStringAsync("/AdminAccess"));
        return await browser.PostAsync("/AdminAccess", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Password"] = password, ["Code"] = Code(key), ["ReturnUrl"] = returnUrl,
            ["MfaEnabled"] = "true", ["RequirePassword"] = "false", ["__RequestVerificationToken"] = csrf
        }));
    }

    [Fact]
    public async Task PasswordLoginCannotAdministerButCanEnrollAuthenticator()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        await Login(browser);
        foreach (var path in new[] { "/Admin", "/AdminServiceRoles" })
        {
            using var response = await browser.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Contains("/AdminAccess", response.Headers.Location!.OriginalString);
        }
        Assert.Contains("Set up your authenticator", await browser.GetStringAsync("/AdminAccess"));
        using var enrollment = await browser.GetAsync("/TwoFactor/EnableAuthenticator");
        Assert.Equal(HttpStatusCode.OK, enrollment.StatusCode);
    }

    [Fact]
    public async Task BothFactorsRequiredAndReturnUrlCannotEscapeAdmin()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        var key = await EnableMfa(factory);
        await Login(browser, key);
        using var wrong = await StepUp(browser, key, "incorrect");
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        using var rejected = await browser.GetAsync("/Admin");
        Assert.Contains("/AdminAccess", rejected.Headers.Location!.OriginalString);
        using var success = await StepUp(browser, key, returnUrl: "https://attacker.example/");
        Assert.Equal(HttpStatusCode.Redirect, success.StatusCode);
        Assert.Equal("/Admin", success.Headers.Location!.OriginalString);
        var cookie = success.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("__Host-Andy.AdminAccess="));
        Assert.Contains("secure", cookie);
        Assert.Contains("httponly", cookie);
        Assert.Contains("samesite=strict", cookie);
        using var allowed = await browser.GetAsync("/Admin/Users");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var another = Browser(factory);
        await Login(another, key);
        another.DefaultRequestHeaders.Add("Cookie", cookie.Split(';')[0]);
        using var copied = await another.GetAsync("/Admin/Users");
        Assert.Equal(HttpStatusCode.Redirect, copied.StatusCode);
        Assert.Contains("/AdminAccess", copied.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task InvalidCodeCountsTowardLockoutAndCsrfIsRequired()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        var key = await EnableMfa(factory);
        await Login(browser, key);
        var csrf = Csrf(await browser.GetStringAsync("/AdminAccess"));
        var fields = new Dictionary<string, string>
            { ["Password"] = CustomWebApplicationFactory.AdminPassword, ["Code"] = "invalid" };
        using var missingCsrf = await browser.PostAsync("/AdminAccess", new FormUrlEncodedContent(fields));
        Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        fields["__RequestVerificationToken"] = csrf;
        using var wrong = await browser.PostAsync("/AdminAccess", new FormUrlEncodedContent(fields));
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = (await users.FindByEmailAsync(CustomWebApplicationFactory.AdminEmail))!;
        Assert.Equal(1, await users.GetAccessFailedCountAsync(user));
        for (var attempt = 1; attempt < users.Options.Lockout.MaxFailedAccessAttempts; attempt++)
        {
            using var again = await browser.PostAsync("/AdminAccess", new FormUrlEncodedContent(fields));
            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        }
        using var lockedScope = factory.Services.CreateScope();
        var lockedUsers = lockedScope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var lockedUser = (await lockedUsers.FindByEmailAsync(CustomWebApplicationFactory.AdminEmail))!;
        Assert.True(await lockedUsers.IsLockedOutAsync(lockedUser));
        using var denied = await browser.GetAsync("/Admin");
        Assert.Contains("/AdminAccess", denied.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("stamp")]
    [InlineData("role")]
    [InlineData("mfa")]
    public async Task CredentialOrPrivilegeChangesInvalidateProof(string change)
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        var key = await EnableMfa(factory);
        await Login(browser, key);
        using var proof = await StepUp(browser, key);
        Assert.Equal(HttpStatusCode.Redirect, proof.StatusCode);
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByEmailAsync(CustomWebApplicationFactory.AdminEmail))!;
            var result = change switch
            {
                "stamp" => await users.UpdateSecurityStampAsync(user),
                "role" => await users.RemoveFromRoleAsync(user, "Admin"),
                _ => await users.SetTwoFactorEnabledAsync(user, false)
            };
            Assert.True(result.Succeeded);
        }
        using var denied = await browser.GetAsync("/Admin/Users");
        Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
        Assert.DoesNotContain("/Admin/Users", denied.Headers.Location!.OriginalString.Split('?')[0]);
    }

    [Fact]
    public async Task ProofExpiresAfterFifteenMinutesWithoutSlidingRenewal()
    {
        using var root = new CustomWebApplicationFactory();
        var clock = new TestClock();
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Configure<CookieAuthenticationOptions>(AdminAccessFilter.Scheme, options => options.TimeProvider = clock)));
        using var browser = Browser(factory);
        var key = await EnableMfa(factory);
        await Login(browser, key);
        using var proof = await StepUp(browser, key);
        Assert.Equal(HttpStatusCode.Redirect, proof.StatusCode);
        clock.Advance(TimeSpan.FromMinutes(10));
        using var active = await browser.GetAsync("/Admin");
        Assert.Equal(HttpStatusCode.OK, active.StatusCode);
        clock.Advance(TimeSpan.FromMinutes(6));
        using var expired = await browser.GetAsync("/Admin");
        Assert.Equal(HttpStatusCode.Redirect, expired.StatusCode);
        Assert.Contains("/AdminAccess", expired.Headers.Location!.OriginalString);
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan delta) => now += delta;
    }

    private static string Code(string key)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        var buffer = 0; var bits = 0;
        foreach (var character in key.ToUpperInvariant())
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character);
            bits += 5;
            if (bits >= 8) { bits -= 8; bytes.Add((byte)(buffer >> bits)); }
        }
        var counter = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
        if (BitConverter.IsLittleEndian) Array.Reverse(counter);
        var hash = HMACSHA1.HashData(bytes.ToArray(), counter);
        var offset = hash[^1] & 15;
        var number = ((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (number % 1000000).ToString("D6");
    }
}
