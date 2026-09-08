using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Andy.Auth.Extensions;
using Andy.Auth.Revocation;
using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services.Revocation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Server;

namespace Andy.Auth.Server.Tests;

public sealed class RevocationDeliveryIntegrationTests
{
    [Fact]
    public async Task RevocationAndOutboxRollBackTogether_AndHardDeletePreservesNotification()
    {
        using var fixture = await Fixture.Create();
        await using (var db = fixture.Db())
        {
            await using var transaction = await db.Database.BeginTransactionAsync();
            (await db.UserSessions.SingleAsync()).IsRevoked = true;
            await db.SaveChangesAsync();
            Assert.Single(await db.RevocationOutbox.ToListAsync());
            await transaction.RollbackAsync();
        }
        await using (var db = fixture.Db())
        {
            Assert.False((await db.UserSessions.SingleAsync()).IsRevoked);
            Assert.Empty(await db.RevocationOutbox.ToListAsync());
            db.Users.Remove(await db.Users.SingleAsync());
            await db.SaveChangesAsync();
            Assert.Empty(await db.UserSessions.ToListAsync());
            Assert.Equal("session-1", (await db.RevocationOutbox.SingleAsync()).SessionId);
        }
    }

    [Theory]
    [InlineData("disable")]
    [InlineData("stamp")]
    [InlineData("session")]
    [InlineData("delete-session")]
    public async Task LifecycleMutationEnqueuesDurably(string mutation)
    {
        using var fixture = await Fixture.Create();
        await using (var db = fixture.Db())
        {
            var user = await db.Users.SingleAsync();
            var session = await db.UserSessions.SingleAsync();
            if (mutation == "disable") user.IsActive = false;
            if (mutation == "stamp") user.SecurityStamp = "next";
            if (mutation == "session") session.IsRevoked = true;
            if (mutation == "delete-session") db.UserSessions.Remove(session);
            db.SaveChanges(); // synchronous stores use the same transactional capture
        }
        await using var read = fixture.Db();
        Assert.Single(await read.RevocationOutbox.ToListAsync());
    }

    [Fact]
    public async Task FailedDeliveryRetries_ReceiptSurvivesRestart_AndReplayCannotRestoreAccess()
    {
        using var fixture = await Fixture.Create();
        using var receiver = await fixture.Receiver();
        using var api = receiver.GetTestClient();
        api.BaseAddress = new Uri("https://receiver.test");
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", fixture.Token("at+jwt", "api"));
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync("/protected")).StatusCode);
        var transport = new RecordingHandler(receiver.GetTestServer().CreateHandler()) { Fail = true };
        using var outbound = new HttpClient(transport);
        await using var db = fixture.Db();
        (await db.UserSessions.SingleAsync()).IsRevoked = true;
        await db.SaveChangesAsync();
        var dispatcher = fixture.Dispatcher(db, outbound);
        Assert.Equal(0, await dispatcher.DispatchAsync());
        Assert.Equal(1, (await db.RevocationOutbox.AsNoTracking().SingleAsync()).Attempts);
        transport.Fail = false;
        Assert.Equal(0, await dispatcher.DispatchAsync()); // respect retry backoff
        fixture.Clock.Offset += TimeSpan.FromSeconds(6);
        transport.LoseAck = true;
        Assert.Equal(0, await dispatcher.DispatchAsync()); // recipient persisted it, but acknowledgment was lost
        Assert.True(await fixture.Store.IsRevokedAsync(Fixture.Issuer, "session-1", default));
        transport.LoseAck = false;
        fixture.Clock.Offset += TimeSpan.FromSeconds(11);
        Assert.Equal(1, await dispatcher.DispatchAsync());
        Assert.Empty(await db.RevocationOutbox.AsNoTracking().ToListAsync());
        Assert.Equal(new JsonWebToken(transport.Tokens[0]).Id, new JsonWebToken(transport.Tokens[1]).Id);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync("/protected")).StatusCode);
        using var restarted = await fixture.Receiver();
        using var replay = restarted.GetTestClient();
        replay.BaseAddress = new Uri("https://receiver.test");
        Assert.Equal(HttpStatusCode.Accepted, (await replay.PostAsync("/auth/events", Set(transport.Tokens[1]))).StatusCode);
        replay.DefaultRequestHeaders.Authorization = api.DefaultRequestHeaders.Authorization;
        Assert.Equal(HttpStatusCode.Unauthorized, (await replay.GetAsync("/protected")).StatusCode);
        fixture.Store.Unavailable = true;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await replay.GetAsync("/protected")).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await replay.PostAsync("/auth/events", Set(transport.Tokens[1]))).StatusCode);
    }

    [Fact]
    public async Task TwoDispatchersCannotOwnTheSameDeliveryLease()
    {
        using var fixture = await Fixture.Create();
        using var receiver = await fixture.Receiver();
        var transport = new RecordingHandler(receiver.GetTestServer().CreateHandler()) { Block = true };
        using var outbound = new HttpClient(transport);
        await using var first = fixture.Db();
        (await first.UserSessions.SingleAsync()).IsRevoked = true;
        await first.SaveChangesAsync();
        await using var second = fixture.Db();
        var sending = fixture.Dispatcher(first, outbound).DispatchAsync();
        await transport.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            Assert.Equal(0, await fixture.Dispatcher(second, outbound).DispatchAsync());
            Assert.Single(transport.Tokens);
        }
        finally { transport.Release.TrySetResult(); }
        Assert.Equal(1, await sending);
    }

    [Theory]
    [InlineData(302)]
    [InlineData(400)]
    public async Task PermanentRefusalIsRetainedForRepair_AndExpiredLeaseCanBeRecovered(int status)
    {
        using var fixture = await Fixture.Create();
        using var receiver = await fixture.Receiver();
        var transport = new RecordingHandler(receiver.GetTestServer().CreateHandler()) { OverrideStatus = (HttpStatusCode)status };
        using var outbound = new HttpClient(transport);
        await using var db = fixture.Db();
        (await db.UserSessions.SingleAsync()).IsRevoked = true;
        await db.SaveChangesAsync();
        var row = await db.RevocationOutbox.SingleAsync();
        row.LeaseToken = "dead-worker";
        row.LeaseUntilUtc = DateTime.UtcNow.AddSeconds(-1);
        await db.SaveChangesAsync();
        var dispatcher = fixture.Dispatcher(db, outbound);
        Assert.Equal(0, await dispatcher.DispatchAsync());
        var retained = await db.RevocationOutbox.AsNoTracking().SingleAsync();
        Assert.Equal("http_" + status, retained.LastError);
        Assert.Equal(DateTime.MaxValue, retained.NextAttemptAtUtc);
        fixture.Clock.Offset += TimeSpan.FromDays(1);
        Assert.Equal(0, await dispatcher.DispatchAsync());
        Assert.Single(transport.Tokens);
    }

    [Theory]
    [InlineData("at+jwt", "receiver", false)]
    [InlineData("secevent+jwt", "wrong", false)]
    [InlineData("secevent+jwt", "receiver", true)]
    public async Task ReceiverRejectsConfusedOrForgedTokens(string type, string audience, bool forged)
    {
        using var fixture = await Fixture.Create();
        using var receiver = await fixture.Receiver();
        using var client = receiver.GetTestClient();
        client.BaseAddress = new Uri("https://receiver.test");
        using var response = await client.PostAsync("/auth/events", Set(fixture.Token(type, audience, forged)));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await fixture.Store.IsRevokedAsync(Fixture.Issuer, "session-1", default));
    }

    private static StringContent Set(string token) => new(token, Encoding.ASCII, "application/secevent+jwt");

    private sealed class Clock : TimeProvider
    {
        public TimeSpan Offset;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

    private sealed class RecordingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public bool Fail, Block, LoseAck;
        public HttpStatusCode? OverrideStatus;
        public List<string> Tokens = new();
        public TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Tokens.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
            Entered.TrySetResult();
            if (Block) await Release.Task.WaitAsync(cancellationToken);
            if (Fail) return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            if (OverrideStatus.HasValue) return new HttpResponseMessage(OverrideStatus.Value);
            var response = await base.SendAsync(request, cancellationToken);
            if (LoseAck) { response.Dispose(); throw new HttpRequestException("acknowledgment lost"); }
            return response;
        }
    }

    private sealed class ClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    // A real durable test recipient database, shared by independent receiver hosts.
    // Production may supply IRevokedSessionStore or the distributed-cache adapter.
    private sealed class SqliteDenials(string path) : IRevokedSessionStore
    {
        public bool Unavailable;
        private async Task<SqliteConnection> Open(CancellationToken ct)
        {
            if (Unavailable) throw new IOException("denial store unavailable");
            var connection = new SqliteConnection("Data Source=" + path + ";Pooling=False");
            await connection.OpenAsync(ct);
            return connection;
        }
        public async Task RevokeAsync(string issuer, string sessionId, CancellationToken cancellationToken)
        {
            await using var connection = await Open(cancellationToken);
            using var command = connection.CreateCommand();
            command.CommandText = "INSERT OR IGNORE INTO Denials(Issuer, Sid) VALUES($issuer, $sid)";
            command.Parameters.AddWithValue("$issuer", issuer);
            command.Parameters.AddWithValue("$sid", sessionId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        public async Task<bool> IsRevokedAsync(string issuer, string sessionId, CancellationToken cancellationToken)
        {
            await using var connection = await Open(cancellationToken);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM Denials WHERE Issuer=$issuer AND Sid=$sid";
            command.Parameters.AddWithValue("$issuer", issuer);
            command.Parameters.AddWithValue("$sid", sessionId);
            return (long)(await command.ExecuteScalarAsync(cancellationToken))! > 0;
        }
    }

    private sealed class Fixture : IDisposable
    {
        public const string Issuer = "https://auth.test/";
        private readonly string directory = Path.Combine(Path.GetTempPath(), "andy-set-" + Guid.NewGuid().ToString("N"));
        private readonly RSA rsa = RSA.Create(2048);
        public readonly Clock Clock = new();
        public SqliteDenials Store = null!;
        private RsaSecurityKey Key => new(rsa) { KeyId = "test-signing" };
        private readonly RevocationDeliveryOptions delivery = new()
        {
            Enabled = true, Targets = new() { new() { Audience = "receiver", Endpoint = "https://receiver.test/auth/events" } }
        };
        public static async Task<Fixture> Create()
        {
            var fixture = new Fixture();
            Directory.CreateDirectory(fixture.directory);
            await using var db = fixture.Db();
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(new ApplicationUser { Id = "user-1", UserName = "test", IsActive = true, SecurityStamp = "first" });
            db.UserSessions.Add(new UserSession { UserId = "user-1", SessionId = "session-1", ExpiresAt = DateTime.UtcNow.AddDays(1), LastActivity = DateTime.UtcNow });
            await db.SaveChangesAsync();
            var receiptPath = Path.Combine(fixture.directory, "receipt.sqlite");
            await using var receipt = new SqliteConnection("Data Source=" + receiptPath + ";Pooling=False");
            await receipt.OpenAsync();
            using var create = receipt.CreateCommand();
            create.CommandText = "CREATE TABLE Denials(Issuer TEXT NOT NULL, Sid TEXT NOT NULL, PRIMARY KEY(Issuer,Sid))";
            await create.ExecuteNonQueryAsync();
            fixture.Store = new SqliteDenials(receiptPath);
            return fixture;
        }
        public ApplicationDbContext Db() => new(new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite("Data Source=" + Path.Combine(directory, "auth.sqlite") + ";Pooling=False").Options, Options.Create(delivery));
        public RevocationDispatcher Dispatcher(ApplicationDbContext db, HttpClient client)
        {
            var options = new OpenIddictServerOptions { Issuer = new Uri(Issuer) };
            options.SigningCredentials.Add(new SigningCredentials(Key, SecurityAlgorithms.RsaSha256));
            var monitor = Mock.Of<IOptionsMonitor<OpenIddictServerOptions>>(value => value.CurrentValue == options);
            return new RevocationDispatcher(db, Options.Create(delivery), monitor, new ClientFactory(client), Clock,
                NullLogger<RevocationDispatcher>.Instance);
        }
        public Task<IHost> Receiver() => new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddSingleton<IRevokedSessionStore>(Store);
            services.AddSingleton<TimeProvider>(Clock);
            services.AddAndyAuth(options => { options.Authority = Issuer; options.Audience = "api"; options.CheckRevocationNotifications = true; });
            services.AddAndyRevocationReceiver(options => { options.Authority = Issuer; options.Audience = "receiver"; });
            var metadata = new OpenIdConnectConfiguration { Issuer = Issuer };
            metadata.SigningKeys.Add(Key);
            services.AddSingleton(provider => new RevocationReceiverKeys(provider.GetRequiredService<IOptions<RevocationReceiverOptions>>(),
                provider.GetRequiredService<IHttpClientFactory>()) { Manager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata) });
            services.PostConfigure<JwtBearerOptions>("Bearer", options =>
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata));
        }).Configure(app =>
        {
            app.UseRouting(); app.UseAuthentication(); app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapAndyRevocationEvents();
                endpoints.MapGet("/protected", context => context.Response.WriteAsync("allowed")).RequireAuthorization();
            });
        })).StartAsync();
        public string Token(string type, string audience, bool forged = false)
        {
            using var other = RSA.Create(2048);
            var now = Clock.GetUtcNow();
            return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                TokenType = type, Issuer = Issuer, Audience = audience, IssuedAt = now.UtcDateTime,
                Expires = now.AddMinutes(5).UtcDateTime,
                SigningCredentials = new SigningCredentials(forged ? new RsaSecurityKey(other) { KeyId = "test-signing" } : Key, SecurityAlgorithms.RsaSha256),
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = "user-1", ["session_id"] = "session-1", ["jti"] = Guid.NewGuid().ToString("N"),
                    ["events"] = new Dictionary<string, object> { [RevocationReceiver.EventType] = new Dictionary<string, object> { ["sid"] = "session-1", ["occurred_at"] = now.ToUnixTimeSeconds() } }
                }
            });
        }
        public void Dispose() { rsa.Dispose(); Directory.Delete(directory, true); }
    }
}
