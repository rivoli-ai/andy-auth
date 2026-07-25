using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// andy-auth#153. `client_secret_expires_at` was computed, persisted and
/// returned in the registration response — and never compared against the
/// clock, so DCR secrets outlived their advertised lifetime indefinitely.
/// The gate also used to be a private helper copied into two controllers.
/// </summary>
public class DcrClientGateTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly DcrClientGate _gate;

    public DcrClientGateTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"TestDb_{Guid.NewGuid()}")
            .Options;
        _dbContext = new ApplicationDbContext(options);
        _gate = new DcrClientGate(_dbContext);
    }

    private async Task SeedAsync(
        string clientId,
        bool isApproved = true,
        bool isDisabled = false,
        long clientSecretExpiresAt = 0)
    {
        _dbContext.DynamicClientRegistrations.Add(new DynamicClientRegistration
        {
            ClientId = clientId,
            RegisteredAt = DateTime.UtcNow,
            IsApproved = isApproved,
            IsDisabled = isDisabled,
            ClientSecretExpiresAt = clientSecretExpiresAt,
        });
        await _dbContext.SaveChangesAsync();
    }

    [Fact]
    public async Task NonDcrClient_IsAllowed()
    {
        // Seeded/manifest clients have no DCR record and no DCR restrictions.
        (await _gate.GetDenialReasonAsync("andy-docs-api")).Should().BeNull();
    }

    [Fact]
    public async Task ApprovedEnabledClient_IsAllowed()
    {
        await SeedAsync("dcr_ok");

        (await _gate.GetDenialReasonAsync("dcr_ok")).Should().BeNull();
    }

    [Fact]
    public async Task UnapprovedClient_IsDenied()
    {
        await SeedAsync("dcr_pending", isApproved: false);

        (await _gate.GetDenialReasonAsync("dcr_pending"))
            .Should().Contain("disabled or pending approval");
    }

    [Fact]
    public async Task DisabledClient_IsDenied()
    {
        await SeedAsync("dcr_off", isDisabled: true);

        (await _gate.GetDenialReasonAsync("dcr_off"))
            .Should().Contain("disabled or pending approval");
    }

    [Fact]
    public async Task ExpiredClientSecret_IsDenied()
    {
        await SeedAsync("dcr_stale",
            clientSecretExpiresAt: DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds());

        (await _gate.GetDenialReasonAsync("dcr_stale"))
            .Should().Contain("client secret has expired");
    }

    [Fact]
    public async Task UnexpiredClientSecret_IsAllowed()
    {
        await SeedAsync("dcr_fresh",
            clientSecretExpiresAt: DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds());

        (await _gate.GetDenialReasonAsync("dcr_fresh")).Should().BeNull();
    }

    [Fact]
    public async Task ZeroExpiry_MeansNeverExpires()
    {
        // RFC 7591 §3.2.1: client_secret_expires_at of 0 means no expiry. It is
        // also the value public clients get, so treating 0 as "expired at the
        // epoch" would lock out every public DCR client.
        await SeedAsync("dcr_forever", clientSecretExpiresAt: 0);

        (await _gate.GetDenialReasonAsync("dcr_forever")).Should().BeNull();
    }

    [Fact]
    public async Task DisabledBeatsExpiry_InReporting()
    {
        // Both conditions true: report the admin action, which is the more
        // actionable of the two.
        await SeedAsync("dcr_both",
            isDisabled: true,
            clientSecretExpiresAt: DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds());

        (await _gate.GetDenialReasonAsync("dcr_both"))
            .Should().Contain("disabled or pending approval");
    }
}
