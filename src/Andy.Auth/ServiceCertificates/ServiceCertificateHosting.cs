using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Andy.Auth.ServiceCertificates;

public static class ServiceCertificateHosting
{
    /// <summary>Configures a dedicated service HTTPS listener. Keep browser/OIDC traffic on a separate listener.</summary>
    public static void ConfigureAndyServiceTls(this HttpsConnectionAdapterOptions https,
        ServiceCertificateOptions options, X509Certificate2 serverCertificate, ServiceCertificateValidator validator)
    {
        if (!options.IsValid()) throw new ArgumentException("Invalid service certificate settings.", nameof(options));
        https.ServerCertificate = serverCertificate;
        https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        https.ClientCertificateMode = options.EffectiveMode switch
        {
            ServiceAuthenticationMode.Jwt => ClientCertificateMode.NoCertificate,
            ServiceAuthenticationMode.Both => ClientCertificateMode.AllowCertificate,
            _ => ClientCertificateMode.RequireCertificate
        };
        https.ClientCertificateValidation = (certificate, _, _) => validator.Validate(certificate).Succeeded;
    }
}
