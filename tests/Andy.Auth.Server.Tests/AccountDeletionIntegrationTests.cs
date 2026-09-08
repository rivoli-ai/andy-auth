using System.Net;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests;

public sealed class AccountDeletionIntegrationTests
{
    private static HttpClient Browser(CustomWebApplicationFactory factory) => factory.CreateClient(new WebApplicationFactoryClientOptions
        { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
    private static string Csrf(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(match.Success);
        return match.Groups[1].Value;
    }
    private static async Task Login(HttpClient browser, bool admin = false)
    {
        var html = await browser.GetStringAsync("/Account/Login");
        using var response = await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = admin ? CustomWebApplicationFactory.AdminEmail : CustomWebApplicationFactory.TestUserEmail,
            ["Password"] = admin ? CustomWebApplicationFactory.AdminPassword : CustomWebApplicationFactory.TestUserPassword,
            ["__RequestVerificationToken"] = Csrf(html)
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }
    private static async Task<HttpResponseMessage> Delete(HttpClient browser, string password = "Test123!", string confirmation = "DELETE")
    {
        var csrf = Csrf(await browser.GetStringAsync("/DeleteAccount"));
        return await browser.PostAsync("/DeleteAccount", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Password"] = password, ["Confirmation"] = confirmation, ["__RequestVerificationToken"] = csrf,
            ["userId"] = "another-user", ["RequirePassword"] = "false", ["RequireSignIn"] = "false"
        }));
    }

    [Theory]
    [InlineData("wrong-password", "DELETE")]
    [InlineData("Test123!", "")]
    public async Task InvalidConfirmationOrPasswordCannotDelete(string password, string confirmation)
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        await Login(browser);
        using var response = await Delete(browser, password, confirmation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        Assert.NotNull(await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>()
            .FindByEmailAsync(CustomWebApplicationFactory.TestUserEmail));
    }

    [Fact]
    public async Task AnonymousCsrfAndSystemAccountBoundariesAreEnforced()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        using var anonymous = await browser.GetAsync("/DeleteAccount");
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        Assert.Contains("/Account/Login", anonymous.Headers.Location!.OriginalString);
        await Login(browser);
        using var noCsrf = await browser.PostAsync("/DeleteAccount", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["Password"] = "Test123!", ["Confirmation"] = "DELETE" }));
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);
        using var admin = Browser(factory);
        await Login(admin, admin: true);
        using var system = await admin.GetAsync("/DeleteAccount");
        Assert.Equal(HttpStatusCode.Redirect, system.StatusCode);
        Assert.Contains("AccessDenied", system.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task OldSessionCannotBeMadeFreshByActivityOrFormFields()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        await Login(browser);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.UserSessions.ExecuteUpdateAsync(s => s.SetProperty(x => x.CreatedAt, DateTime.UtcNow.AddMinutes(-6))
                .SetProperty(x => x.LastActivity, DateTime.UtcNow));
        }
        using var response = await Delete(browser);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Sign in again", await response.Content.ReadAsStringAsync());
        using var verify = factory.Services.CreateScope();
        Assert.NotNull(await verify.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>()
            .FindByEmailAsync(CustomWebApplicationFactory.TestUserEmail));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeletesOnlySignedInUserAndAllLocalArtifacts(bool externalOnly)
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        using var otherSession = Browser(factory);
        await Login(browser);
        await Login(otherSession);
        string userId;
        using (var scope = factory.Services.CreateScope())
        {
            var services = scope.ServiceProvider;
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByEmailAsync(CustomWebApplicationFactory.TestUserEmail))!;
            userId = user.Id;
            if (externalOnly) Assert.True((await users.RemovePasswordAsync(user)).Succeeded);
            Assert.True((await users.AddLoginAsync(user, new UserLoginInfo("TestProvider", "external-key", "Test"))).Succeeded);
            var db = services.GetRequiredService<ApplicationDbContext>();
            db.UserConsents.Add(new UserConsent { UserId = userId, ClientId = "docs", Scopes = "openid" });
            db.ConsentGrants.Add(new ConsentGrant { UserId = userId, GrantId = "delete-grant", ClientId = "docs", RequestedScopes = "openid", GrantedScopes = "openid" });
            db.OAuthAuthorizations.Add(new OAuthAuthorization { SubjectId = userId, Provider = "github" });
            db.OAuthAuthorizations.Add(new OAuthAuthorization { SubjectId = "another-user", Provider = "github" });
            db.AuditLogs.Add(new AuditLog { Action = "OtherUser", PerformedById = "another-user" });
            db.AuditLogs.Add(new AuditLog { Action = "Targeted", PerformedById = "another-user", TargetUserId = userId, TargetUserEmail = user.Email });
            var initialToken = new InitialAccessToken { Name = "personal", TokenHash = "delete-hash", CreatedById = userId, CreatedByEmail = user.Email! };
            db.InitialAccessTokens.Add(initialToken);
            db.DynamicClientRegistrations.Add(new DynamicClientRegistration
                { ClientId = "shared-client", InitialAccessToken = initialToken, ApprovedById = userId, DisabledBy = userId });
            var group = new Andy.Auth.Server.Data.Group { Code = "delete-test", Name = "Test" };
            db.Groups.Add(group);
            db.UserGroups.Add(new UserGroup { UserId = userId, Group = group });
            await db.SaveChangesAsync();
            await services.GetRequiredService<IOpenIddictAuthorizationManager>().CreateAsync(new OpenIddictAuthorizationDescriptor
                { Subject = userId, Status = "valid", Type = "permanent" });
            await services.GetRequiredService<IOpenIddictTokenManager>().CreateAsync(new OpenIddictTokenDescriptor
                { Subject = userId, Status = "valid", Type = "refresh_token" });
        }
        using var response = await Delete(browser, externalOnly ? "" : "Test123!");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        using var verify = factory.Services.CreateScope();
        var db2 = verify.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.False(await db2.Users.AnyAsync(u => u.Id == userId));
        Assert.True(await db2.Users.AnyAsync(u => u.Email == CustomWebApplicationFactory.AdminEmail));
        Assert.False(await db2.UserSessions.AnyAsync(s => s.UserId == userId));
        Assert.False(await db2.UserConsents.AnyAsync(s => s.UserId == userId));
        Assert.False(await db2.ConsentGrants.AnyAsync(s => s.UserId == userId));
        Assert.False(await db2.UserGroups.AnyAsync(s => s.UserId == userId));
        Assert.False(await db2.UserLogins.AnyAsync(s => s.UserId == userId));
        Assert.False(await db2.UserRoles.AnyAsync(s => s.UserId == userId));
        Assert.False(await db2.OAuthAuthorizations.AnyAsync(s => s.SubjectId == userId));
        Assert.True(await db2.OAuthAuthorizations.AnyAsync(s => s.SubjectId == "another-user"));
        Assert.False(await db2.AuditLogs.AnyAsync(s => s.PerformedById == userId || s.TargetUserId == userId));
        Assert.True(await db2.AuditLogs.AnyAsync(s => s.Action == "OtherUser"));
        Assert.False(await db2.InitialAccessTokens.AnyAsync(t => t.CreatedById == userId));
        var sharedClient = await db2.DynamicClientRegistrations.SingleAsync(c => c.ClientId == "shared-client");
        Assert.Null(sharedClient.InitialAccessTokenId);
        Assert.Null(sharedClient.ApprovedById);
        Assert.Null(sharedClient.DisabledBy);
        await foreach (var _ in verify.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().FindBySubjectAsync(userId)) Assert.Fail("Token survived deletion");
        await foreach (var _ in verify.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>().FindBySubjectAsync(userId)) Assert.Fail("Authorization survived deletion");
        using var staleSession = await otherSession.GetAsync("/DeleteAccount");
        Assert.Equal(HttpStatusCode.Redirect, staleSession.StatusCode);
        Assert.Contains("/Account/Login", staleSession.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task DatabaseFailureRollsBackAllDeletedArtifacts()
    {
        using var factory = new CustomWebApplicationFactory();
        using var browser = Browser(factory);
        await Login(browser);
        string userId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            userId = (await db.Users.SingleAsync(u => u.Email == CustomWebApplicationFactory.TestUserEmail)).Id;
            db.OAuthAuthorizations.Add(new OAuthAuthorization { SubjectId = userId, Provider = "github" });
            await db.SaveChangesAsync();
            await scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().CreateAsync(new OpenIddictTokenDescriptor
                { Subject = userId, Status = "valid", Type = "refresh_token" });
            await db.Database.ExecuteSqlRawAsync("CREATE TRIGGER reject_delete BEFORE DELETE ON AspNetUsers BEGIN SELECT RAISE(ABORT, 'test deletion failure'); END;");
        }
        using var response = await Delete(browser);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("could not be deleted", await response.Content.ReadAsStringAsync());
        using var verify = factory.Services.CreateScope();
        var db2 = verify.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.True(await db2.Users.AnyAsync(u => u.Id == userId));
        Assert.True(await db2.OAuthAuthorizations.AnyAsync(a => a.SubjectId == userId));
        var count = 0;
        await foreach (var _ in verify.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().FindBySubjectAsync(userId)) count++;
        Assert.Equal(1, count);
    }
}
