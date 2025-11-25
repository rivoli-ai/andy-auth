using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Database context for Andy Auth Server.
/// Includes ASP.NET Core Identity and OpenIddict entities.
/// </summary>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Audit logs for tracking administrative actions.
    /// </summary>
    public DbSet<AuditLog> AuditLogs { get; set; }

    /// <summary>
    /// User consent records for OAuth applications.
    /// </summary>
    public DbSet<UserConsent> UserConsents { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure OpenIddict entities
        builder.UseOpenIddict();

        // Customize Identity tables if needed
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(u => u.FullName).HasMaxLength(200);
            entity.Property(u => u.ProfilePictureUrl).HasMaxLength(500);
            entity.HasIndex(u => u.Email).IsUnique();
        });

        // Configure UserConsent entity
        builder.Entity<UserConsent>(entity =>
        {
            entity.HasIndex(c => new { c.UserId, c.ClientId }).IsUnique();
            entity.HasIndex(c => c.ClientId);
            entity.HasOne(c => c.User)
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
