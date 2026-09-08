using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services.Ciba;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Playwright;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Tests;

public sealed class CibaIntegrationTests
{
    [RedisFact]
    public async Task PushEnrollment_Approval_AndPollingIssueSessionBoundTokens()
    {
        using var factory = new CibaFactory();
        using var browser = await Login(factory);
        await ConfigureClient(factory);
        using var deviceKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var point = deviceKey.ExportParameters(false).Q;
        var encodedKey = Base64UrlEncoder.Encode(new byte[] { 4 }.Concat(point.X!).Concat(point.Y!).ToArray());
        var deviceAuth = RandomNumberGenerator.GetBytes(16);
        var devicePage = await browser.GetStringAsync("/Ciba/Device");
        using var enrolled = await browser.PostAsync("/Ciba/Device", Form(new()
        {
            ["endpoint"] = "https://push.example/send/device", ["p256dh"] = encodedKey,
            ["auth"] = Base64UrlEncoder.Encode(deviceAuth), ["password"] = CustomWebApplicationFactory.AdminPassword,
            ["__RequestVerificationToken"] = Csrf(devicePage)
        }));
        Assert.True(enrolled.IsSuccessStatusCode, await enrolled.Content.ReadAsStringAsync());
        using var client = Client(factory);
        using var start = await client.PostAsync("/connect/bc-authorize", Form(StartForm()));
        Assert.True(start.IsSuccessStatusCode, await start.Content.ReadAsStringAsync());
        using var started = JsonDocument.Parse(await start.Content.ReadAsStringAsync());
        var requestId = started.RootElement.GetProperty("auth_req_id").GetString()!;
        Assert.Equal(5, started.RootElement.GetProperty("interval").GetInt32());
        factory.Clock.Advance(6);
        using var pending = await Poll(client, requestId);
        Assert.Equal("authorization_pending", await Error(pending));
        using var early = await Poll(client, requestId);
        Assert.Equal("slow_down", await Error(early));
        string approvalId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var row = await db.CibaAuthentications.SingleAsync();
            approvalId = row.Id;
            Assert.DoesNotContain(requestId, row.RequestHash);
            Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<CibaPushDelivery>().DispatchAsync());
            Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<CibaPushDelivery>().DispatchAsync());
        }
        Assert.Equal(1, factory.Push.Count);
        Assert.NotEmpty(factory.Push.Ciphertext!);
        Assert.DoesNotContain("TEST-123", System.Text.Encoding.UTF8.GetString(factory.Push.Ciphertext!));
        Assert.NotNull(factory.Push.Authorization);
        using var notification = JsonDocument.Parse(DecryptPush(factory.Push.Ciphertext!, deviceKey, deviceAuth));
        Assert.Equal("TEST-123", notification.RootElement.GetProperty("body").GetString());
        var notifiedUri = new Uri(notification.RootElement.GetProperty("url").GetString()!);
        Assert.Equal("/Ciba/Approve/" + approvalId, notifiedUri.AbsolutePath);
        var approval = await browser.GetStringAsync(notifiedUri.PathAndQuery);
        Assert.Contains("TEST-123", approval);
        using var wrongPassword = await browser.PostAsync("/Ciba/Approve/" + approvalId, Form(new()
        { ["decision"] = "allow", ["password"] = "wrong", ["__RequestVerificationToken"] = Csrf(approval) }));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        using var accepted = await browser.PostAsync("/Ciba/Approve/" + approvalId, Form(new()
        { ["decision"] = "allow", ["password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = Csrf(approval) }));
        Assert.True(accepted.IsSuccessStatusCode, await accepted.Content.ReadAsStringAsync());
        factory.Clock.Advance(11);
        using var issued = await Poll(client, requestId);
        Assert.True(issued.IsSuccessStatusCode, await issued.Content.ReadAsStringAsync());
        using var tokens = JsonDocument.Parse(await issued.Content.ReadAsStringAsync());
        var access = new JsonWebToken(tokens.RootElement.GetProperty("access_token").GetString()!);
        Assert.NotEmpty(access.GetClaim("session_id").Value);
        Assert.NotEmpty(tokens.RootElement.GetProperty("id_token").GetString()!);
        Assert.NotEmpty(tokens.RootElement.GetProperty("refresh_token").GetString()!);
        using var replay = await Poll(client, requestId);
        Assert.Equal("invalid_grant", await Error(replay));
        using var metadata = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        Assert.Equal(metadata.RootElement.GetProperty("issuer").GetString()!.TrimEnd('/') + "/connect/bc-authorize",
            metadata.RootElement.GetProperty("backchannel_authentication_endpoint").GetString());
    }

    [RedisFact]
    public async Task AuthenticationValidationAndNotificationThrottle_RejectInvalidRequests()
    {
        using var factory = new CibaFactory();
        using var client = Client(factory);
        await ConfigureClient(factory);
        await SeedDevice(factory);
        var cases = new (string Parameter, string? Value, string Error)[]
        {
            ("client_secret", "wrong", "invalid_client"), ("client_id", "absent", "invalid_client"),
            ("login_hint", null, "invalid_request"), ("login_hint", "unknown@example.com", "unknown_user_id"),
            ("id_token_hint", "extra", "invalid_request"), ("login_hint_token", "extra", "invalid_request"),
            ("requested_expiry", "0", "invalid_request"), ("requested_expiry", "-1", "invalid_request"),
            ("scope", "roles", "invalid_scope"), ("scope", "openid unregistered", "invalid_scope"),
            ("binding_message", "bad\nmessage", "invalid_binding_message"), ("request", "unsigned", "invalid_request")
        };
        foreach (var (parameter, value, expected) in cases)
        {
            var form = StartForm();
            if (value == null) form.Remove(parameter); else form[parameter] = value;
            using var response = await client.PostAsync("/connect/bc-authorize", Form(form));
            Assert.Equal(expected, await Error(response));
        }
        var requests = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ => client.PostAsync("/connect/bc-authorize", Form(StartForm()))));
        try
        {
            Assert.Equal(1, requests.Count(response => response.IsSuccessStatusCode));
            Assert.Equal(23, requests.Count(response => response.StatusCode == HttpStatusCode.TooManyRequests));
        }
        finally { foreach (var response in requests) response.Dispose(); }
    }

    [RedisFact]
    public async Task ApprovalRequiresCsrfAndExactUser_DenialAndExpiryStayTerminal()
    {
        using var factory = new CibaFactory();
        using var browser = await Login(factory);
        using var client = Client(factory);
        await ConfigureClient(factory);
        await SeedDevice(factory);
        var (opaque, id) = await Begin(client, factory);
        using var noCsrf = await browser.PostAsync("/Ciba/Approve/" + id, Form(new() { ["decision"] = "allow", ["password"] = CustomWebApplicationFactory.AdminPassword }));
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);
        using var anonymous = await client.GetAsync("/Ciba/Approve/" + id);
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        var page = await browser.GetStringAsync("/Ciba/Approve/" + id);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.CibaAuthentications.Where(row => row.Id == id).ExecuteUpdateAsync(setters => setters.SetProperty(row => row.UserId, "another-user"));
        }
        using var wrongUser = await browser.PostAsync("/Ciba/Approve/" + id, Form(new()
        { ["decision"] = "allow", ["password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = Csrf(page) }));
        Assert.Equal(HttpStatusCode.NotFound, wrongUser.StatusCode);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userId = await db.Users.Where(row => row.Email == CustomWebApplicationFactory.AdminEmail).Select(row => row.Id).SingleAsync();
            await db.CibaAuthentications.Where(row => row.Id == id).ExecuteUpdateAsync(setters => setters.SetProperty(row => row.UserId, userId));
        }
        using var denied = await browser.PostAsync("/Ciba/Approve/" + id, Form(new() { ["decision"] = "deny", ["__RequestVerificationToken"] = Csrf(page) }));
        Assert.True(denied.IsSuccessStatusCode);
        using var denial = await Poll(client, opaque);
        Assert.Equal("access_denied", await Error(denial));
        using var approveAfterDenial = await browser.PostAsync("/Ciba/Approve/" + id, Form(new()
        { ["decision"] = "allow", ["password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = Csrf(page) }));
        Assert.Equal(HttpStatusCode.NotFound, approveAfterDenial.StatusCode);
        factory.Clock.Advance(301);
        using var expired = await Poll(client, opaque);
        Assert.Equal("expired_token", await Error(expired));
        using var unknown = await Poll(client, "not-issued");
        Assert.Equal("invalid_grant", await Error(unknown));
    }

    [RedisFact]
    public async Task DeliveryFailureRetries_AfterDispatcherRestart_AndExpiryStopsDelivery()
    {
        using var factory = new CibaFactory();
        using var client = Client(factory);
        await ConfigureClient(factory);
        await SeedDevice(factory);
        await Begin(client, factory);
        factory.Push.Status = HttpStatusCode.ServiceUnavailable;
        using (var scope = factory.Services.CreateScope())
            Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<CibaPushDelivery>().DispatchAsync());
        factory.Clock.Advance(6);
        factory.Push.Status = HttpStatusCode.Created;
        using (var scope = factory.Services.CreateScope())
            Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<CibaPushDelivery>().DispatchAsync());
        Assert.Equal(2, factory.Push.Count);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.CibaAuthentications.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.PushDelivered, false));
        }
        factory.Clock.Advance(301);
        using (var scope = factory.Services.CreateScope())
            Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<CibaPushDelivery>().DispatchAsync());
        Assert.Equal(2, factory.Push.Count);
    }

    [RedisFact]
    public async Task MobileBrowserApproval_SubmitsRealCsrfForm_ThenPollsTokens()
    {
        using var factory = new CibaFactory();
        using var session = await Login(factory);
        using var client = Client(factory);
        await ConfigureClient(factory);
        await SeedDevice(factory);
        var (opaque, id) = await Begin(client, factory);
        using var playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new() { Headless = true });
        await using var context = await browser.NewContextAsync(new() { ViewportSize = new() { Width = 375, Height = 812 }, IsMobile = true });
        var page = await context.NewPageAsync();
        // Bridge browser HTTP to the full application's TestServer. The same
        // authenticated cookie jar backs each request; forms and CSRF run normally.
        await page.RouteAsync("**/*", async route =>
        {
            if (!route.Request.Url.StartsWith("https://localhost/", StringComparison.Ordinal)) { await route.AbortAsync(); return; }
            using var request = new HttpRequestMessage(new HttpMethod(route.Request.Method), route.Request.Url);
            if (route.Request.PostDataBuffer != null)
            {
                request.Content = new ByteArrayContent(route.Request.PostDataBuffer);
                if (route.Request.Headers.TryGetValue("content-type", out var type)) request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(type);
            }
            using var response = await session.SendAsync(request);
            var headers = response.Headers.Concat(response.Content.Headers).Where(pair => pair.Key is not ("Set-Cookie" or "Content-Length" or "Transfer-Encoding"))
                .ToDictionary(pair => pair.Key, pair => string.Join(", ", pair.Value));
            await route.FulfillAsync(new() { Status = (int)response.StatusCode, Headers = headers, BodyBytes = await response.Content.ReadAsByteArrayAsync() });
        });
        await page.GotoAsync("https://localhost/Ciba/Approve/" + id);
        await Microsoft.Playwright.Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = "Approve sign-in" })).ToBeVisibleAsync();
        Assert.True(await page.EvaluateAsync<bool>("document.documentElement.scrollWidth <= window.innerWidth"));
        await page.GetByLabel("Confirm your password to approve").FillAsync(CustomWebApplicationFactory.AdminPassword);
        await page.GetByRole(AriaRole.Button, new() { Name = "Approve sign-in" }).ClickAsync();
        await Microsoft.Playwright.Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = "Sign-in approved" })).ToBeVisibleAsync();
        factory.Clock.Advance(6);
        var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ => Poll(client, opaque)));
        try { Assert.Equal(1, results.Count(response => response.IsSuccessStatusCode)); }
        finally { foreach (var response in results) response.Dispose(); }
    }

    [RedisFact]
    public async Task ApprovalRequiresFreshMfa_WhenAccountHasAnAuthenticator()
    {
        using var factory = new CibaFactory();
        using var client = Client(factory);
        await ConfigureClient(factory);
        await SeedDevice(factory);
        string key;
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByEmailAsync(CustomWebApplicationFactory.AdminEmail))!;
            Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
            Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
            key = (await users.GetAuthenticatorKeyAsync(user))!;
        }
        using var browser = await Login(factory, key);
        var (opaque, id) = await Begin(client, factory);
        var page = await browser.GetStringAsync("/Ciba/Approve/" + id);
        var decision = new Dictionary<string, string> { ["decision"] = "allow", ["password"] = CustomWebApplicationFactory.AdminPassword,
            ["__RequestVerificationToken"] = Csrf(page) };
        using var noCode = await browser.PostAsync("/Ciba/Approve/" + id, Form(decision));
        Assert.Equal(HttpStatusCode.Unauthorized, noCode.StatusCode);
        decision["code"] = Code(key);
        using var approved = await browser.PostAsync("/Ciba/Approve/" + id, Form(decision));
        Assert.True(approved.IsSuccessStatusCode);
        factory.Clock.Advance(6);
        using var issued = await Poll(client, opaque);
        Assert.True(issued.IsSuccessStatusCode, await issued.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(await issued.Content.ReadAsStringAsync());
        var identity = new JsonWebToken(body.RootElement.GetProperty("id_token").GetString()!);
        Assert.Contains("otp", identity.GetPayloadValue<string[]>("amr"));
    }

    [RedisFact]
    public async Task RevokedSessionOrChangedAccount_PreventsApprovedRequestRedemption()
    {
        foreach (var mutation in new[] { "revoked", "disabled", "locked", "deleted", "missing", "stamp", "mode", "permission", "outage" })
        {
            using var factory = new CibaFactory();
            using var browser = await Login(factory);
            using var client = Client(factory);
            await ConfigureClient(factory);
            await SeedDevice(factory);
            var (opaque, id) = await Begin(client, factory);
            var page = await browser.GetStringAsync("/Ciba/Approve/" + id);
            using var approved = await browser.PostAsync("/Ciba/Approve/" + id, Form(new()
            { ["decision"] = "allow", ["password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = Csrf(page) }));
            Assert.True(approved.IsSuccessStatusCode);
            using (var scope = factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var row = await db.CibaAuthentications.SingleAsync();
                var user = await db.Users.SingleAsync(user => user.Id == row.UserId);
                if (mutation is "mode" or "permission")
                {
                    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                    var app = (await manager.FindByClientIdAsync("andy-docs-api"))!;
                    var descriptor = new OpenIddictApplicationDescriptor();
                    await manager.PopulateAsync(descriptor, app);
                    if (mutation == "mode") descriptor.Properties[CibaOptions.DeliveryModeProperty] = JsonSerializer.SerializeToElement("push");
                    else descriptor.Permissions.Remove(OpenIddictConstants.Permissions.Prefixes.Scope + "roles");
                    await manager.UpdateAsync(app, descriptor);
                }
                else if (mutation == "outage") await db.Database.ExecuteSqlRawAsync("DROP TABLE UserSessions");
                else
                {
                    var session = await db.UserSessions.SingleAsync(session => session.SessionId == row.SessionId);
                    if (mutation == "revoked") session.IsRevoked = true;
                    if (mutation == "missing") db.UserSessions.Remove(session);
                    if (mutation == "disabled") user.IsActive = false;
                    if (mutation == "stamp") user.SecurityStamp = Guid.NewGuid().ToString();
                    if (mutation == "deleted") user.DeletedAt = DateTime.UtcNow;
                    if (mutation == "locked") { user.LockoutEnabled = true; user.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1); }
                    await db.SaveChangesAsync();
                }
            }
            factory.Clock.Advance(6);
            using var rejected = await Poll(client, opaque);
            if (mutation == "outage") Assert.Equal(HttpStatusCode.ServiceUnavailable, rejected.StatusCode);
            Assert.Equal(mutation switch { "mode" => "unauthorized_client", "permission" => "invalid_scope", "outage" => "temporarily_unavailable", _ => "access_denied" }, await Error(rejected));
        }
    }

    [Fact]
    public async Task DisabledFlow_IsAbsentFromDiscoveryAndRejectsInitiation()
    {
        using var factory = new CustomWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        using var metadata = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        Assert.False(metadata.RootElement.TryGetProperty("backchannel_authentication_endpoint", out _));
        using var response = await client.PostAsync("/connect/bc-authorize", Form(StartForm()));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [RedisFact]
    public async Task BasicClientAuthentication_Works_AndAnotherClientCannotRedeemTheRequest()
    {
        using var factory = new CibaFactory();
        using var client = Client(factory);
        await ConfigureClient(factory);
        await ConfigureClient(factory, "andy-containers-api");
        await SeedDevice(factory);
        var form = StartForm(); form.Remove("client_id"); form.Remove("client_secret");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes(
            "andy-docs-api:" + CustomWebApplicationFactory.AndyDocsApiClientSecret)));
        var correctAuthentication = client.DefaultRequestHeaders.Authorization;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes("andy-docs-api:wrong")));
        using var badBasic = await client.PostAsync("/connect/bc-authorize", Form(form));
        Assert.Equal(HttpStatusCode.Unauthorized, badBasic.StatusCode);
        Assert.Equal("Basic", badBasic.Headers.WwwAuthenticate.Single().Scheme);
        client.DefaultRequestHeaders.Authorization = correctAuthentication;
        using var start = await client.PostAsync("/connect/bc-authorize", Form(form));
        Assert.True(start.IsSuccessStatusCode, await start.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(await start.Content.ReadAsStringAsync());
        client.DefaultRequestHeaders.Authorization = null;
        using var wrongClient = await client.PostAsync("/connect/token", Form(new()
        {
            ["client_id"] = "andy-containers-api", ["client_secret"] = "andy-containers-api-secret-change-in-production",
            ["grant_type"] = CibaOptions.GrantType, ["auth_req_id"] = body.RootElement.GetProperty("auth_req_id").GetString()!
        }));
        Assert.Equal("invalid_grant", await Error(wrongClient));
        using var browser = await Login(factory);
        var page = await browser.GetStringAsync("/Ciba/Device");
        using var ssrf = await browser.PostAsync("/Ciba/Device", Form(new()
        {
            ["endpoint"] = "https://127.0.0.1/internal", ["p256dh"] = "invalid", ["auth"] = "invalid",
            ["password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = Csrf(page)
        }));
        Assert.Equal(HttpStatusCode.BadRequest, ssrf.StatusCode);
    }

    private static async Task<(string Opaque, string Id)> Begin(HttpClient client, CibaFactory factory)
    {
        using var response = await client.PostAsync("/connect/bc-authorize", Form(StartForm()));
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var opaque = body.RootElement.GetProperty("auth_req_id").GetString()!;
        using var scope = factory.Services.CreateScope();
        var row = await scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().CibaAuthentications.SingleAsync();
        return (opaque, row.Id);
    }
    private static async Task SeedDevice(CibaFactory factory)
    {
        using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var point = ec.ExportParameters(false).Q;
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userId = await db.Users.Where(row => row.Email == CustomWebApplicationFactory.AdminEmail).Select(row => row.Id).SingleAsync();
        var subscription = new CibaSubscription("https://push.example/send/device", Base64UrlEncoder.Encode(new byte[] { 4 }.Concat(point.X!).Concat(point.Y!).ToArray()),
            Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)));
        db.CibaPushDevices.Add(new CibaPushDevice { UserId = userId, EndpointHash = CibaService.Hash(subscription.Endpoint),
            ProtectedSubscription = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector(CibaPushDelivery.ProtectionPurpose)
                .Protect(JsonSerializer.Serialize(subscription)) });
        await db.SaveChangesAsync();
    }
    private static byte[] DecryptPush(byte[] payload, ECDiffieHellman device, byte[] authenticationSecret)
    {
        Assert.Equal(65, payload[20]);
        var sender = payload[21..86];
        using var peer = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = sender[1..33], Y = sender[33..65] } });
        var point = device.ExportParameters(false).Q;
        var devicePublic = new byte[] { 4 }.Concat(point.X!).Concat(point.Y!).ToArray();
        var info = Encoding.ASCII.GetBytes("WebPush: info\0").Concat(devicePublic).Concat(sender).ToArray();
        var ikm = HKDF.DeriveKey(HashAlgorithmName.SHA256, device.DeriveRawSecretAgreement(peer.PublicKey), 32, authenticationSecret, info);
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, payload[..16], Encoding.ASCII.GetBytes("Content-Encoding: aes128gcm\0"));
        var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 12, payload[..16], Encoding.ASCII.GetBytes("Content-Encoding: nonce\0"));
        var plaintext = new byte[payload.Length - 86 - 16];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, payload.AsSpan(86, plaintext.Length), payload.AsSpan(payload.Length - 16), plaintext);
        var delimiter = Array.FindLastIndex(plaintext, value => value != 0);
        Assert.Equal(2, plaintext[delimiter]);
        return plaintext[..delimiter];
    }

    private static async Task ConfigureClient(CibaFactory factory, string clientId = "andy-docs-api")
    {
        using var scope = factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = (await manager.FindByClientIdAsync(clientId))!;
        var descriptor = new OpenIddictApplicationDescriptor();
        await manager.PopulateAsync(descriptor, app);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.GrantType + CibaOptions.GrantType);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + "roles");
        descriptor.Properties[CibaOptions.DeliveryModeProperty] = JsonSerializer.SerializeToElement("poll");
        await manager.UpdateAsync(app, descriptor);
    }
    private static Dictionary<string, string> StartForm() => new()
    {
        ["client_id"] = "andy-docs-api", ["client_secret"] = CustomWebApplicationFactory.AndyDocsApiClientSecret,
        ["login_hint"] = CustomWebApplicationFactory.AdminEmail, ["scope"] = "openid roles offline_access urn:andy-docs-api", ["binding_message"] = "TEST-123"
    };
    private static Task<HttpResponseMessage> Poll(HttpClient client, string id) => client.PostAsync("/connect/token", Form(new()
    {
        ["client_id"] = "andy-docs-api", ["client_secret"] = CustomWebApplicationFactory.AndyDocsApiClientSecret,
        ["grant_type"] = CibaOptions.GrantType, ["auth_req_id"] = id
    }));
    private static FormUrlEncodedContent Form(Dictionary<string, string> form) => new(form);
    private static string Csrf(string html) => WebUtility.HtmlDecode(Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
    private static HttpClient Client(CibaFactory factory) => factory.CreateClient(new WebApplicationFactoryClientOptions
    { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
    private static async Task<HttpClient> Login(CibaFactory factory, string? key = null)
    {
        var client = Client(factory);
        var csrf = Csrf(await client.GetStringAsync("/Account/Login"));
        using var response = await client.PostAsync("/Account/Login", Form(new()
        { ["Email"] = CustomWebApplicationFactory.AdminEmail, ["Password"] = CustomWebApplicationFactory.AdminPassword, ["__RequestVerificationToken"] = csrf }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        if (key != null)
        {
            var mfaCsrf = Csrf(await client.GetStringAsync(response.Headers.Location));
            using var mfa = await client.PostAsync("/Account/LoginWith2fa", Form(new()
                { ["TwoFactorCode"] = Code(key), ["__RequestVerificationToken"] = mfaCsrf }));
            Assert.Equal(HttpStatusCode.Redirect, mfa.StatusCode);
        }
        return client;
    }
    private static async Task<string?> Error(HttpResponseMessage response)
    {
        Assert.False(response.IsSuccessStatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("error").GetString();
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
    private sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(int seconds) => now = now.AddSeconds(seconds);
    }
    private sealed class PushHandler : HttpMessageHandler
    {
        public int Count;
        public HttpStatusCode Status = HttpStatusCode.Created;
        public byte[]? Ciphertext;
        public AuthenticationHeaderValue? Authorization;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Count++;
            Ciphertext = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            Authorization = request.Headers.Authorization;
            Assert.Equal("https://push.example/send/device", request.RequestUri!.AbsoluteUri);
            return new(Status);
        }
    }
    private sealed class CibaFactory : CustomWebApplicationFactory
    {
        private readonly Dictionary<string, string?> previous = new();
        public MutableClock Clock { get; } = new();
        public PushHandler Push { get; } = new();
        public CibaFactory()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var key = ec.ExportParameters(true);
            Set("OpenIddict__AdvancedFlows__CIBA__Enabled", "true");
            Set("OpenIddict__AdvancedFlows__CIBA__VapidPublicKey", Base64UrlEncoder.Encode(new byte[] { 4 }.Concat(key.Q.X!).Concat(key.Q.Y!).ToArray()));
            Set("OpenIddict__AdvancedFlows__CIBA__VapidPrivateKey", Base64UrlEncoder.Encode(key.D!));
            Set("OpenIddict__AdvancedFlows__CIBA__VapidSubject", "mailto:operator@example.com");
            Set("RateLimiting__RedisConnectionString", Environment.GetEnvironmentVariable("ANDY_TEST_REDIS")!);
        }
        private void Set(string key, string value) { previous[key] = Environment.GetEnvironmentVariable(key); Environment.SetEnvironmentVariable(key, value); }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
            {
                foreach (var descriptor in services.Where(item => item.ServiceType == typeof(IHostedService) && item.ImplementationType == typeof(CibaPushWorker)).ToArray()) services.Remove(descriptor);
                services.Replace(ServiceDescriptor.Singleton<TimeProvider>(Clock));
                services.Configure<CibaOptions>(options => options.PushOrigins = ["https://push.example"]);
                services.Configure<IpRateLimitOptions>(options => options.GeneralRules = new());
                services.AddHttpClient(CibaPushDelivery.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Push);
            });
        }
        protected override void Dispose(bool disposing)
        {
            foreach (var pair in previous) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            base.Dispose(disposing);
        }
    }
}
