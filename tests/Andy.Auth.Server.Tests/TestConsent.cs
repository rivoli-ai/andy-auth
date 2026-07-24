using Andy.Auth.Server.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace Andy.Auth.Server.Tests;

internal static class TestConsent
{
    /// <summary>
    /// Real ticket service over an ephemeral key ring — the crypto is the
    /// point of andy-auth#124, so these tests exercise it rather than a mock.
    /// </summary>
    internal static ConsentTicketService CreateConsentTicketService() =>
        new(Microsoft.AspNetCore.DataProtection.DataProtectionProvider.Create(
                new DirectoryInfo(Path.Combine(Path.GetTempPath(), "andy-auth-tests-dp"))),
            new Mock<ILogger<ConsentTicketService>>().Object);
}
