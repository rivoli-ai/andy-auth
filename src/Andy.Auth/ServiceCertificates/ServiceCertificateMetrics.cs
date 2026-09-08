using System.Diagnostics.Metrics;

namespace Andy.Auth.ServiceCertificates;

internal static class ServiceCertificateMetrics
{
    private static readonly Meter Meter = new("Andy.Auth.ServiceCertificates");
    internal static readonly Counter<long> Rotations = Meter.CreateCounter<long>("andy.mtls.certificate.rotations");
    internal static readonly Counter<long> Rejected = Meter.CreateCounter<long>("andy.mtls.authentication.rejected");
    internal static readonly Histogram<double> RemainingLifetime = Meter.CreateHistogram<double>("andy.mtls.certificate.remaining", "s");
}
