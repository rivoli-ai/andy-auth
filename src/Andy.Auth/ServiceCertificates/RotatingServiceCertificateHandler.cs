using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace Andy.Auth.ServiceCertificates;

/// <summary>Switches connection pools when PEM material changes; old response streams retain their pool until disposal.</summary>
public sealed class RotatingServiceCertificateHandler(IOptionsMonitor<ServiceCertificateOptions> configuration,
    ServiceCertificateValidator validator, TimeProvider clock) : HttpMessageHandler
{
    private readonly object gate = new();
    private Generation? current;
    private bool disposed;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is not { Scheme: "https" }) throw new HttpRequestException("Service certificate requests require HTTPS.");
        Generation generation;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var options = configuration.CurrentValue;
            if (!options.IsValid() || !ServiceCertificateOptions.IsServiceIdentity(options.LocalServiceIdentity) ||
                !ServiceCertificateOptions.IsServiceIdentity(options.ExpectedServerIdentity))
                throw new HttpRequestException("Invalid outbound service certificate configuration.");
            // Read complete files each request so replacement or trust withdrawal never leaves a stale pool active.
            // Operators publish cert/key pairs atomically through a versioned directory symlink.
            var certificatePem = ServiceCertificateValidator.ReadBounded(options.CertificatePath);
            var keyPem = ServiceCertificateValidator.ReadBounded(options.PrivateKeyPath ?? options.CertificatePath);
            var trustPem = ServiceCertificateValidator.ReadBounded(options.TrustBundlePath);
            var fingerprint = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
                certificatePem + "\0" + keyPem + "\0" + trustPem + "\0" + options.LocalServiceIdentity + "\0" + options.ExpectedServerIdentity)));
            if (current?.Fingerprint != fingerprint)
            {
                using var imported = X509Certificate2.CreateFromPem(certificatePem, keyPem);
                var certificate = X509CertificateLoader.LoadPkcs12(imported.Export(X509ContentType.Pkcs12), null,
                    OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet);
                var validation = validator.ValidateLocal(certificate, options.LocalServiceIdentity);
                if (!validation.Succeeded) { certificate.Dispose(); throw new HttpRequestException(validation.Error); }
                var expectedIdentity = options.ExpectedServerIdentity;
                var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    ConnectTimeout = TimeSpan.FromSeconds(5),
                    PooledConnectionLifetime = TimeSpan.FromMinutes(1),
                    PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        ClientCertificates = new X509CertificateCollection { certificate },
                        RemoteCertificateValidationCallback = (_, peer, _, errors) =>
                        {
                            if (peer is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                            using var remote = new X509Certificate2(peer);
                            return validator.Validate(remote, expectedIdentity).Succeeded;
                        }
                    }
                };
                var next = new Generation(fingerprint, certificate, handler);
                var old = current;
                current = next;
                ServiceCertificateMetrics.Rotations.Add(1);
                old?.Retire();
            }
            generation = current;
            if (generation.Certificate.NotAfter.ToUniversalTime() <= clock.GetUtcNow().UtcDateTime)
                throw new HttpRequestException("Local service certificate expired.");
            ServiceCertificateMetrics.RemainingLifetime.Record((generation.Certificate.NotAfter.ToUniversalTime() - clock.GetUtcNow().UtcDateTime).TotalSeconds);
            generation.Acquire();
        }
        try
        {
            var response = await generation.Client.SendAsync(request, cancellationToken);
            response.Content = new LeasedContent(response.Content, generation);
            return response;
        }
        catch { generation.Release(); throw; }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) lock (gate) { disposed = true; current?.Retire(); current = null; }
        base.Dispose(disposing);
    }

    private sealed class Generation(string fingerprint, X509Certificate2 certificate, HttpMessageHandler handler)
    {
        private int references = 1;
        public string Fingerprint { get; } = fingerprint;
        public X509Certificate2 Certificate { get; } = certificate;
        public HttpMessageInvoker Client { get; } = new(handler, true);
        public void Acquire() => Interlocked.Increment(ref references);
        public void Retire() => Release();
        public void Release()
        {
            if (Interlocked.Decrement(ref references) == 0) { Client.Dispose(); Certificate.Dispose(); }
        }
    }

    private sealed class LeasedContent : HttpContent
    {
        private readonly HttpContent inner;
        private Generation? generation;
        public LeasedContent(HttpContent content, Generation owner)
        {
            inner = content; generation = owner;
            foreach (var header in content.Headers) Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => inner.CopyToAsync(stream);
        protected override Task<Stream> CreateContentReadStreamAsync() => inner.ReadAsStreamAsync();
        protected override bool TryComputeLength(out long length) { length = inner.Headers.ContentLength ?? 0; return inner.Headers.ContentLength.HasValue; }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { inner.Dispose(); }
                finally { Interlocked.Exchange(ref generation, null)?.Release(); }
            }
            base.Dispose(disposing);
        }
    }
}
