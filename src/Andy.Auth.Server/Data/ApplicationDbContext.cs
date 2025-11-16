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
    }
}
