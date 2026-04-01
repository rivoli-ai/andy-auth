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

    /// <summary>
    /// Active user sessions for session management.
    /// </summary>
    public DbSet<UserSession> UserSessions { get; set; }

    /// <summary>
    /// Registration access tokens for dynamically registered clients.
    /// </summary>
    public DbSet<RegistrationAccessToken> RegistrationAccessTokens { get; set; }

    /// <summary>
    /// Initial access tokens for controlled client registration.
    /// </summary>
    public DbSet<InitialAccessToken> InitialAccessTokens { get; set; }

    /// <summary>
    /// Metadata for dynamically registered clients.
    /// </summary>
    public DbSet<DynamicClientRegistration> DynamicClientRegistrations { get; set; }

    /// <summary>
    /// Groups that users can belong to.
    /// </summary>
    public DbSet<Group> Groups { get; set; }

    /// <summary>
    /// User-to-group memberships.
    /// </summary>
    public DbSet<UserGroup> UserGroups { get; set; }

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

        // Configure UserSession entity
        builder.Entity<UserSession>(entity =>
        {
            entity.HasIndex(s => s.SessionId).IsUnique();
            entity.HasIndex(s => s.UserId);
            entity.HasIndex(s => new { s.UserId, s.IsRevoked });
            entity.HasOne(s => s.User)
                .WithMany()
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure RegistrationAccessToken entity
        builder.Entity<RegistrationAccessToken>(entity =>
        {
            entity.HasIndex(t => t.ClientId).IsUnique();
            entity.HasIndex(t => t.TokenHash);
            entity.Property(t => t.ClientId).HasMaxLength(100).IsRequired();
            entity.Property(t => t.TokenHash).HasMaxLength(128).IsRequired();
        });

        // Configure InitialAccessToken entity
        builder.Entity<InitialAccessToken>(entity =>
        {
            entity.HasIndex(t => t.TokenHash);
            entity.Property(t => t.Name).HasMaxLength(200).IsRequired();
            entity.Property(t => t.TokenHash).HasMaxLength(128).IsRequired();
            entity.Property(t => t.CreatedById).HasMaxLength(450).IsRequired();
            entity.Property(t => t.CreatedByEmail).HasMaxLength(256).IsRequired();
        });

        // Configure DynamicClientRegistration entity
        builder.Entity<DynamicClientRegistration>(entity =>
        {
            entity.HasIndex(d => d.ClientId).IsUnique();
            entity.Property(d => d.ClientId).HasMaxLength(100).IsRequired();
            entity.HasOne(d => d.InitialAccessToken)
                .WithMany()
                .HasForeignKey(d => d.InitialAccessTokenId)
                .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(d => d.RegistrationAccessToken)
                .WithMany()
                .HasForeignKey("RegistrationAccessTokenId")
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure Group entity
        builder.Entity<Group>(entity =>
        {
            entity.HasIndex(g => g.Code).IsUnique();
            entity.Property(g => g.Code).HasMaxLength(100).IsRequired();
            entity.Property(g => g.Name).HasMaxLength(200).IsRequired();
            entity.Property(g => g.Source).HasMaxLength(50).HasDefaultValue("local");
            entity.Property(g => g.ExternalId).HasMaxLength(500);
        });

        // Configure UserGroup entity
        builder.Entity<UserGroup>(entity =>
        {
            entity.HasIndex(ug => new { ug.UserId, ug.GroupId }).IsUnique();
            entity.Property(ug => ug.Source).HasMaxLength(50).HasDefaultValue("manual");
            entity.HasOne(ug => ug.User)
                .WithMany()
                .HasForeignKey(ug => ug.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(ug => ug.Group)
                .WithMany(g => g.UserGroups)
                .HasForeignKey(ug => ug.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
