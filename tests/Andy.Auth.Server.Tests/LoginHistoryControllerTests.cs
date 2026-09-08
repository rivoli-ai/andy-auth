using System.Security.Claims;
using Andy.Auth.Server.Controllers;
using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Andy.Auth.Server.Tests;

public sealed class LoginHistoryControllerTests
{
    [Fact]
    public async Task Index_IsolatesUserAndLoginActions_AndPaginatesWithoutDuplicates()
    {
        await using var db = new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        for (var i = 0; i < 55; i++)
            db.AuditLogs.Add(new AuditLog { PerformedById = "me", Action = "UserLogin", IpAddress = "127.0.0.1" });
        db.AuditLogs.Add(new AuditLog { PerformedById = "other", Action = "UserLogin" });
        db.AuditLogs.Add(new AuditLog { PerformedById = "me", Action = "UserDeleted" });
        await db.SaveChangesAsync();
        var controller = CreateController(db, "me");
        var first = Assert.IsType<LoginHistoryViewModel>(Assert.IsType<ViewResult>(await controller.Index()).Model);
        Assert.Equal(50, first.Entries.Count);
        Assert.All(first.Entries, entry => Assert.Equal("127.0.0.1", entry.IpAddress));
        Assert.NotNull(first.NextCursor);
        var second = Assert.IsType<LoginHistoryViewModel>(Assert.IsType<ViewResult>(await controller.Index(first.NextCursor)).Model);
        Assert.Equal(5, second.Entries.Count);
        Assert.Null(second.NextCursor);
        Assert.Empty(first.Entries.Select(e => e.Id).Intersect(second.Entries.Select(e => e.Id)));
    }

    [Fact]
    public async Task Index_RejectsMissingIdentityAndInvalidCursor()
    {
        await using var db = new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        Assert.IsType<ChallengeResult>(await CreateController(db, null).Index());
        Assert.IsType<BadRequestResult>(await CreateController(db, "me").Index(0));
    }

    private static LoginHistoryController CreateController(ApplicationDbContext db, string? id) => new(db)
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(id is null ? Array.Empty<Claim>() :
                    new[] { new Claim(ClaimTypes.NameIdentifier, id) }, "Test"))
            }
        }
    };
}
