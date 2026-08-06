using Andy.Auth.Server.Data;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Tests.Services;

public sealed class DcrApprovalConcurrencyTests
{
    [Fact]
    public async Task StaleApproval_CannotOverwritePendingMetadataReview()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite(connection)
            .Options;

        await using (var setup = new ApplicationDbContext(options))
        {
            await setup.Database.EnsureCreatedAsync();
            setup.DynamicClientRegistrations.Add(new DynamicClientRegistration
            {
                ClientId = "dcr_concurrent",
                RequiresApproval = true,
                IsApproved = true,
                ApprovedById = "admin-original",
                ApprovedAt = DateTime.UtcNow.AddDays(-1)
            });
            await setup.SaveChangesAsync();
        }

        await using var staleAdminContext = new ApplicationDbContext(options);
        await using var updateContext = new ApplicationDbContext(options);
        var staleAdminCopy = await staleAdminContext.DynamicClientRegistrations.SingleAsync();
        var registrationUpdate = await updateContext.DynamicClientRegistrations.SingleAsync();

        registrationUpdate.IsApproved = false;
        registrationUpdate.ApprovedById = null;
        registrationUpdate.ApprovedAt = null;
        registrationUpdate.MetadataJson = "{\"proposedRedirectUris\":[\"https://new.example/callback\"]}";
        await updateContext.SaveChangesAsync();

        // This approval was based on the pre-update screen. MetadataJson is an
        // optimistic concurrency token, so its stale NULL original value must
        // no longer match the pending-review row.
        staleAdminCopy.ApprovedById = "admin-stale";
        staleAdminCopy.ApprovedAt = DateTime.UtcNow;

        var act = () => staleAdminContext.SaveChangesAsync();
        await act.Should().ThrowAsync<DbUpdateConcurrencyException>();

        await using var verification = new ApplicationDbContext(options);
        var saved = await verification.DynamicClientRegistrations.SingleAsync();
        saved.IsApproved.Should().BeFalse();
        saved.MetadataJson.Should().Contain("new.example");
    }
}
