using Andy.Auth.Server.Services.Revocation;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Data;

public partial class ApplicationDbContext
{
    private readonly RevocationDeliveryOptions _revocationOptions;
    public DbSet<RevocationOutboxMessage> RevocationOutbox => Set<RevocationOutboxMessage>();

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        if (_revocationOptions.Enabled)
        {
            var (sessions, users) = ChangedRevocationSubjects();
            if (users.Count > 0)
                sessions.UnionWith(UserSessions.AsNoTracking().Where(session => users.Contains(session.UserId) && !session.IsRevoked).Select(session => session.SessionId));
            EnqueueRevocations(sessions);
        }
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        if (_revocationOptions.Enabled)
        {
            var (sessions, users) = ChangedRevocationSubjects();
            if (users.Count > 0)
                sessions.UnionWith(await UserSessions.AsNoTracking().Where(session => users.Contains(session.UserId) && !session.IsRevoked)
                    .Select(session => session.SessionId).ToListAsync(cancellationToken));
            EnqueueRevocations(sessions);
        }
        return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private (HashSet<string> Sessions, HashSet<string> Users) ChangedRevocationSubjects()
    {
        ChangeTracker.DetectChanges();
        var sessions = ChangeTracker.Entries<UserSession>().Where(entry =>
            entry.State == EntityState.Deleted ||
            entry.State == EntityState.Added && entry.Entity.IsRevoked ||
            entry.State == EntityState.Modified &&
            (entry.Entity.IsRevoked && !entry.Property(session => session.IsRevoked).OriginalValue ||
             entry.Property(session => session.UserId).OriginalValue != entry.Entity.UserId))
            .Select(entry => entry.Entity.SessionId).ToHashSet(StringComparer.Ordinal);
        var users = ChangeTracker.Entries<ApplicationUser>().Where(entry =>
            entry.State == EntityState.Deleted || entry.State == EntityState.Modified &&
            (!entry.Entity.IsActive && entry.Property(user => user.IsActive).OriginalValue ||
             entry.Entity.DeletedAt != null && entry.Property(user => user.DeletedAt).OriginalValue == null ||
             entry.Entity.SecurityStamp != entry.Property(user => user.SecurityStamp).OriginalValue))
            .Select(entry => entry.Entity.Id).ToHashSet(StringComparer.Ordinal);
        return (sessions, users);
    }

    private void EnqueueRevocations(HashSet<string> sessions)
    {
        // SaveChanges may be retried with the same tracked mutation/outbox entries.
        var pending = ChangeTracker.Entries<RevocationOutboxMessage>().Where(entry => entry.State == EntityState.Added)
            .Select(entry => (entry.Entity.SessionId, entry.Entity.Recipient)).ToHashSet();
        var now = DateTime.UtcNow;
        foreach (var session in sessions)
        foreach (var target in _revocationOptions.Targets)
            if (pending.Add((session, target.Audience)))
                RevocationOutbox.Add(new RevocationOutboxMessage
                {
                    SessionId = session, Recipient = target.Audience, CreatedAtUtc = now, NextAttemptAtUtc = now
                });
    }
}
