using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Data;

public partial class ApplicationDbContext
{
    public DbSet<CibaAuthentication> CibaAuthentications { get; set; }
    public DbSet<CibaPushDevice> CibaPushDevices { get; set; }
    private static void ConfigureCiba(ModelBuilder builder)
    {
        builder.Entity<CibaAuthentication>(entity =>
        {
            entity.HasKey(row => row.Id);
            entity.Property(row => row.Id).HasMaxLength(32);
            entity.Property(row => row.RequestHash).HasMaxLength(64).IsRequired();
            entity.HasIndex(row => row.RequestHash).IsUnique();
            entity.Property(row => row.ClientId).HasMaxLength(256).IsRequired();
            entity.Property(row => row.UserId).HasMaxLength(450).IsRequired();
            entity.Property(row => row.Scope).HasMaxLength(2048).IsRequired();
            entity.Property(row => row.BindingMessage).HasMaxLength(128).IsRequired();
            entity.Property(row => row.Status).HasMaxLength(16).IsRequired();
            entity.Property(row => row.SessionId).HasMaxLength(256);
            entity.Property(row => row.SecurityStampHash).HasMaxLength(64);
            entity.Property(row => row.PushLease).HasMaxLength(32);
            entity.HasIndex(row => new { row.PushDelivered, row.NextPushAtUtc });
            entity.HasIndex(row => row.ExpiresAtUtc);
        });
        builder.Entity<CibaPushDevice>(entity =>
        {
            entity.HasKey(row => row.UserId);
            entity.Property(row => row.UserId).HasMaxLength(450);
            entity.Property(row => row.EndpointHash).HasMaxLength(64).IsRequired();
            entity.HasIndex(row => row.EndpointHash).IsUnique();
            entity.Property(row => row.ProtectedSubscription).HasMaxLength(8192).IsRequired();
            entity.HasOne<ApplicationUser>().WithMany().HasForeignKey(row => row.UserId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
