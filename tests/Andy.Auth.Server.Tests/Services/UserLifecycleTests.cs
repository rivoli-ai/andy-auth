using Andy.Auth.Server.Data;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// andy-auth#146. `IsSuspended`, `ExpiresAt` and `DeletedAt` were written by
/// the admin surfaces but read by no authentication path — suspending or
/// expiring a user did nothing. These lock the predicate that every
/// credential-minting path now shares.
/// </summary>
public class UserLifecycleTests
{
    private static ApplicationUser HealthyUser() => new()
    {
        Id = "user-1",
        Email = "user@test.local",
        IsActive = true,
    };

    [Fact]
    public void HealthyAccount_MayAuthenticate()
    {
        UserLifecycle.GetDenialReason(HealthyUser()).Should().BeNull();
        UserLifecycle.CanAuthenticate(HealthyUser()).Should().BeTrue();
    }

    [Fact]
    public void SuspendedAccount_IsDenied()
    {
        // The regression that motivated the issue: AdminController.SuspendUser
        // sets IsSuspended and leaves IsActive alone, so an IsActive-only check
        // let suspended users straight through.
        var user = HealthyUser();
        user.IsSuspended = true;

        UserLifecycle.GetDenialReason(user).Should().Be("account is suspended");
    }

    [Fact]
    public void InactiveAccount_IsDenied()
    {
        var user = HealthyUser();
        user.IsActive = false;

        UserLifecycle.GetDenialReason(user).Should().Be("account is inactive");
    }

    [Fact]
    public void SoftDeletedAccount_IsDenied()
    {
        var user = HealthyUser();
        user.DeletedAt = DateTime.UtcNow.AddDays(-1);

        UserLifecycle.GetDenialReason(user).Should().Be("account is deleted");
    }

    [Fact]
    public void ExpiredAccount_IsDenied()
    {
        var now = new DateTime(2026, 7, 24, 12, 0, 0, DateTimeKind.Utc);
        var user = HealthyUser();
        user.ExpiresAt = now.AddSeconds(-1);

        UserLifecycle.GetDenialReason(user, now).Should().Be("account expired");
    }

    [Fact]
    public void ExpiryInTheFuture_IsAllowed()
    {
        var now = new DateTime(2026, 7, 24, 12, 0, 0, DateTimeKind.Utc);
        var user = HealthyUser();
        user.ExpiresAt = now.AddSeconds(1);

        UserLifecycle.GetDenialReason(user, now).Should().BeNull();
    }

    [Fact]
    public void ExpiryExactlyNow_IsDenied()
    {
        // Boundary: ExpiresAt is documented "user cannot login after this
        // date", so the instant itself is already past.
        var now = new DateTime(2026, 7, 24, 12, 0, 0, DateTimeKind.Utc);
        var user = HealthyUser();
        user.ExpiresAt = now;

        UserLifecycle.GetDenialReason(user, now).Should().Be("account expired");
    }

    [Fact]
    public void NoExpiry_IsAllowed()
    {
        var user = HealthyUser();
        user.ExpiresAt = null;

        UserLifecycle.GetDenialReason(user).Should().BeNull();
    }
}
