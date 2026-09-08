using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Andy.Auth.ServiceCertificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;

namespace Andy.Auth.Tests.ServiceCertificates;

public sealed class ServiceCertificateTests : IDisposable
{
    private readonly string bundle = Path.Combine(Path.GetTempPath(), "andy-mtls-" + Guid.NewGuid().ToString("N") + ".pem");
    private readonly ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 root;
    private readonly ServiceCertificateOptions settings;
    private readonly Mock<IHostEnvironment> environment = new();
    private readonly DateTimeOffset now = DateTimeOffset.UtcNow;

    public ServiceCertificateTests()
    {
        var request = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        root = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        File.WriteAllText(bundle, root.ExportCertificatePem());
        settings = new ServiceCertificateOptions { Mode = ServiceAuthenticationMode.Both, TrustBundlePath = bundle, AllowDevelopmentNoRevocation = true };
        settings.AllowedClientIdentities.Add("urn:andy:policies", "policies-client");
        environment.SetupGet(value => value.EnvironmentName).Returns("Testing");
    }

    private ServiceCertificateValidator Validator()
    {
        var monitor = new Mock<IOptionsMonitor<ServiceCertificateOptions>>();
        monitor.SetupGet(value => value.CurrentValue).Returns(settings);
        return new(monitor.Object, environment.Object, TimeProvider.System);
    }

    private X509Certificate2 Leaf(string identity = "urn:andy:policies", string purpose = "1.3.6.1.5.5.7.3.2", int minutes = 4, bool ca = false, string? crlUrl = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=ignored-untrusted-name", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(purpose) }, true));
        var names = new SubjectAlternativeNameBuilder();
        names.AddUri(new Uri(identity));
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        if (crlUrl is not null) request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(new[] { crlUrl }));
        using var certificate = request.Create(root, now.AddSeconds(-5), now.AddMinutes(minutes), RandomNumberGenerator.GetBytes(16));
        return certificate.CopyWithPrivateKey(key);
    }

    [Fact]
    public void RegisteredService_MapsToExplicitSubject()
    {
        using var certificate = Leaf();
        var result = Validator().Validate(certificate);
        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("policies-client", result.Subject);
    }

    [Theory]
    [InlineData("urn:andy:unknown", "1.3.6.1.5.5.7.3.2", 4, false, "unregistered_service")]
    [InlineData("urn:andy:policies", "1.3.6.1.5.5.7.3.1", 4, false, "certificate_purpose")]
    [InlineData("urn:andy:policies", "1.3.6.1.5.5.7.3.2", 9, false, "certificate_lifetime")]
    [InlineData("urn:andy:policies", "1.3.6.1.5.5.7.3.2", 4, true, "ca_certificate_is_not_a_service")]
    public void InvalidLeaf_IsRejected(string identity, string purpose, int minutes, bool ca, string error)
    {
        using var certificate = Leaf(identity, purpose, minutes, ca);
        Assert.Equal(error, Validator().Validate(certificate).Error);
    }

    [Fact]
    public void ServerIdentity_IsCheckedIndependentlyOfTrustedIssuer()
    {
        using var certificate = Leaf("urn:andy:rbac", "1.3.6.1.5.5.7.3.1");
        Assert.True(Validator().Validate(certificate, "urn:andy:rbac").Succeeded);
        Assert.Equal("wrong_server_identity", Validator().Validate(certificate, "urn:andy:auth").Error);
    }

    [Fact]
    public void Production_CannotDisableRevocation()
    {
        environment.SetupGet(value => value.EnvironmentName).Returns("Production");
        using var certificate = Leaf();
        var result = Validator().Validate(certificate);
        Assert.True(result.Unavailable);
        Assert.Equal("revocation_checks_required", result.Error);
    }

    [Fact]
    public void Production_WithoutRevocationInformation_FailsClosed()
    {
        settings.AllowDevelopmentNoRevocation = false;
        environment.SetupGet(value => value.EnvironmentName).Returns("Production");
        using var certificate = Leaf();
        Assert.False(Validator().Validate(certificate).Succeeded);
    }

    [Fact]
    public void RemovedTrust_IsNotKeptInMemory()
    {
        using var certificate = Leaf();
        var validator = Validator();
        Assert.True(validator.Validate(certificate).Succeeded);
        File.WriteAllText(bundle, "");
        Assert.False(validator.Validate(certificate).Succeeded);
        File.Delete(bundle);
        Assert.True(validator.Validate(certificate).Unavailable);
    }

    [Theory]
    [InlineData(ServiceAuthenticationMode.Jwt, "none", true, 200, "Bearer")]
    [InlineData(ServiceAuthenticationMode.Jwt, "valid", false, 401, "")]
    [InlineData(ServiceAuthenticationMode.Both, "none", true, 200, "Bearer")]
    [InlineData(ServiceAuthenticationMode.Both, "valid", true, 200, "Andy.ClientCertificate")]
    [InlineData(ServiceAuthenticationMode.Both, "invalid", true, 401, "")]
    [InlineData(ServiceAuthenticationMode.ClientCertificate, "none", true, 401, "")]
    [InlineData(ServiceAuthenticationMode.ClientCertificate, "valid", false, 200, "Andy.ClientCertificate")]
    public async Task ModeSelection_PreservesCertificatePrecedenceAndBearerRollback(ServiceAuthenticationMode mode,
        string presented, bool bearer, int status, string scheme)
    {
        settings.Mode = mode;
        using var certificate = Leaf(presented == "invalid" ? "urn:andy:unregistered" : "urn:andy:policies");
        var monitor = new Mock<IOptionsMonitor<ServiceCertificateOptions>>();
        monitor.SetupGet(value => value.CurrentValue).Returns(settings);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Services.AddAndyServiceAuthentication(new ConfigurationBuilder().Build())
            .AddScheme<AuthenticationSchemeOptions, TestBearerHandler>("Bearer", _ => { });
        builder.Services.AddSingleton(monitor.Object);
        builder.Services.AddAuthorization();
        await using var app = builder.Build();
        app.Use(async (context, next) =>
        {
            // This fixture isolates scheme selection; the separate real TLS test verifies possession.
            if (presented != "none") context.Connection.ClientCertificate = certificate;
            await next();
        });
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/", (HttpContext context) => context.User.Identity!.AuthenticationType!)
            .RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = ServiceCertificateAuthentication.Scheme });
        await app.StartAsync();
        using var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        if (bearer) client.DefaultRequestHeaders.Authorization = new("Bearer", "fixture");
        using var response = await client.GetAsync("/");
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200) Assert.Equal(scheme, await response.Content.ReadAsStringAsync());
    }

    private sealed class TestBearerHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(
            Request.Headers.Authorization == "Bearer fixture"
                ? AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "jwt-service") }, Scheme.Name)), Scheme.Name))
                : AuthenticateResult.NoResult());
    }

    [Fact]
    public async Task RealTls_RotationPreservesOpenResponseAndChangesNextCallerCertificate()
    {
        using var serverCertificate = Leaf("urn:andy:rbac", "1.3.6.1.5.5.7.3.1");
        using var first = Leaf();
        using var second = Leaf();
        var material = bundle + ".client.pem";
        string Export(X509Certificate2 certificate)
        {
            using var key = certificate.GetECDsaPrivateKey();
            return certificate.ExportCertificatePem() + "\n" + key!.ExportPkcs8PrivateKeyPem();
        }
        File.WriteAllText(material, Export(first));
        settings.CertificatePath = material;
        settings.LocalServiceIdentity = "urn:andy:policies";
        settings.ExpectedServerIdentity = "urn:andy:rbac";
        var monitor = new Mock<IOptionsMonitor<ServiceCertificateOptions>>();
        monitor.SetupGet(value => value.CurrentValue).Returns(settings);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) => Validator().Validate(certificate).Succeeded;
        })));
        builder.Services.AddAndyServiceAuthentication(new ConfigurationBuilder().Build());
        builder.Services.AddSingleton(monitor.Object);
        builder.Services.AddAuthorization();
        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        app.MapGet("/stream", async context =>
        {
            await context.Response.WriteAsync("started\n");
            await context.Response.Body.FlushAsync();
            await release.Task.WaitAsync(context.RequestAborted);
            await context.Response.WriteAsync("finished");
        }).RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = ServiceCertificateAuthentication.Scheme });
        app.MapGet("/identity", (HttpContext context) => context.User.FindFirst("certificate_sha256")!.Value)
            .RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = ServiceCertificateAuthentication.Scheme });
        try
        {
            await app.StartAsync();
            using var client = new HttpClient(new RotatingServiceCertificateHandler(monitor.Object, Validator(), TimeProvider.System))
                { BaseAddress = new Uri(app.Urls.Single().Replace("127.0.0.1", "localhost")), Timeout = TimeSpan.FromSeconds(15) };
            Assert.Equal(first.GetCertHashString(HashAlgorithmName.SHA256), await client.GetStringAsync("/identity"));
            using (var anonymousHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate is not null && Validator().Validate(certificate, "urn:andy:rbac").Succeeded
            })
            using (var anonymous = new HttpClient(anonymousHandler) { BaseAddress = client.BaseAddress })
            {
                anonymous.DefaultRequestHeaders.Add("X-Forwarded-Client-Cert", first.ExportCertificatePem().Replace("\n", ""));
                await Assert.ThrowsAsync<HttpRequestException>(() => anonymous.GetStringAsync("/identity"));
            }
            using var stream = await client.GetAsync("/stream", HttpCompletionOption.ResponseHeadersRead);
            File.WriteAllText(material, Export(second));
            Assert.Equal(second.GetCertHashString(HashAlgorithmName.SHA256), await client.GetStringAsync("/identity"));
            release.TrySetResult();
            Assert.Equal("started\nfinished", await stream.Content.ReadAsStringAsync());
            settings.ExpectedServerIdentity = "urn:andy:other-service";
            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetStringAsync("/identity"));
            settings.ExpectedServerIdentity = "urn:andy:rbac";
            // Trust withdrawal also applies to an already pooled connection.
            File.WriteAllText(bundle, "");
            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetStringAsync("/identity"));
        }
        finally { release.TrySetResult(); await app.StopAsync(); File.Delete(material); }
    }

    [LinuxCrlFact]
    public async Task PublishedRevocation_RejectsNextRequestOnExistingTlsConnection()
    {
        settings.AllowDevelopmentNoRevocation = false;
        environment.SetupGet(value => value.EnvironmentName).Returns("Production");
        var crlBuilder = WebApplication.CreateBuilder();
        crlBuilder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0));
        await using var crlServer = crlBuilder.Build();
        byte[] crl = Array.Empty<byte>();
        crlServer.MapGet("/service.crl", async context =>
        {
            context.Response.ContentType = "application/pkix-crl";
            await context.Response.Body.WriteAsync(Volatile.Read(ref crl));
        });
        await crlServer.StartAsync();
        var crlUrl = crlServer.Urls.Single() + "/service.crl";
        using var caller = Leaf(crlUrl: crlUrl);
        using var server = Leaf("urn:andy:rbac", "1.3.6.1.5.5.7.3.1", crlUrl: crlUrl);
        var list = new CertificateRevocationListBuilder();
        crl = list.Build(root, 1, DateTimeOffset.UtcNow.AddSeconds(3), HashAlgorithmName.SHA256,
            thisUpdate: DateTimeOffset.UtcNow.AddSeconds(-1));
        var monitor = new Mock<IOptionsMonitor<ServiceCertificateOptions>>();
        monitor.SetupGet(value => value.CurrentValue).Returns(settings);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0,
            listen => listen.UseHttps(https => https.ConfigureAndyServiceTls(settings, server, Validator()))));
        builder.Services.AddAndyServiceAuthentication(new ConfigurationBuilder().Build());
        builder.Services.AddSingleton(monitor.Object);
        builder.Services.AddAuthorization();
        await using var app = builder.Build();
        var connections = new System.Collections.Concurrent.ConcurrentQueue<string>();
        app.Use(async (context, next) => { connections.Enqueue(context.Connection.Id); await next(); });
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/", () => "accepted").RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute
            { AuthenticationSchemes = ServiceCertificateAuthentication.Scheme });
        await app.StartAsync();
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                    certificate is not null && (errors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
                    Validator().Validate(certificate, "urn:andy:rbac").Succeeded
            };
            handler.ClientCertificates.Add(caller);
            using var client = new HttpClient(handler) { BaseAddress = new Uri(app.Urls.Single().Replace("127.0.0.1", "localhost")), Timeout = TimeSpan.FromSeconds(15) };
            Assert.Equal("accepted", await client.GetStringAsync("/"));
            list.AddEntry(caller, DateTimeOffset.UtcNow, X509RevocationReason.KeyCompromise);
            Volatile.Write(ref crl, list.Build(root, 2, DateTimeOffset.UtcNow.AddMinutes(1), HashAlgorithmName.SHA256,
                thisUpdate: DateTimeOffset.UtcNow));
            // The old signed CRL's nextUpdate bounds cache reuse; no OS cache deletion is used.
            await Task.Delay(TimeSpan.FromSeconds(4));
            using var rejected = await client.GetAsync("/");
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
            var observed = connections.ToArray();
            Assert.Equal(2, observed.Length);
            Assert.Equal(observed[0], observed[1]);
        }
        finally { await app.StopAsync(); await crlServer.StopAsync(); }
    }

    private sealed class LinuxCrlFactAttribute : FactAttribute
    {
        public LinuxCrlFactAttribute()
        {
            if (!OperatingSystem.IsLinux()) Skip = "Online CRL cache acceptance targets the Linux/OpenSSL deployment and runs in required Linux CI.";
        }
    }

    public void Dispose() { File.Delete(bundle); root.Dispose(); rootKey.Dispose(); }
}
