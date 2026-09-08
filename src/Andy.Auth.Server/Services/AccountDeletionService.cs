using Andy.Auth.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Andy.Auth.Server.Services;

/// <summary>Removes local account data atomically, including stores without a user foreign key.</summary>
public sealed class AccountDeletionService(ApplicationDbContext db, UserManager<ApplicationUser> users,
    IOpenIddictTokenManager tokens, IOpenIddictAuthorizationManager authorizations)
{
    public async Task DeleteAsync(ApplicationUser user)
    {
        if (user.IsSystemUser) throw new InvalidOperationException("System accounts cannot be deleted.");
        await using var transaction = await db.Database.BeginTransactionAsync();

        // Use the managers so their caches are invalidated as well as the database rows.
        var userTokens = new List<object>();
        await foreach (var token in tokens.FindBySubjectAsync(user.Id)) userTokens.Add(token);
        foreach (var token in userTokens) await tokens.DeleteAsync(token);
        var grants = new List<object>();
        await foreach (var grant in authorizations.FindBySubjectAsync(user.Id)) grants.Add(grant);
        foreach (var grant in grants) await authorizations.DeleteAsync(grant);

        await db.OAuthAuthorizations.Where(a => a.SubjectId == user.Id).ExecuteDeleteAsync();
        await db.AuditLogs.Where(a => a.PerformedById == user.Id || a.TargetUserId == user.Id ||
            (user.Email != null && (a.PerformedByEmail == user.Email || a.TargetUserEmail == user.Email)))
            .ExecuteDeleteAsync();
        // Registration clients are shared resources: remove the user's attribution and
        // creation credentials, while retaining the clients and their approval state.
        await db.InitialAccessTokens.Where(t => t.CreatedById == user.Id).ExecuteDeleteAsync();
        await db.InitialAccessTokens.Where(t => t.RevokedBy == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedBy, (string?)null));
        await db.DynamicClientRegistrations.Where(c => c.ApprovedById == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.ApprovedById, (string?)null));
        await db.DynamicClientRegistrations.Where(c => c.DisabledBy == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.DisabledBy, (string?)null));

        // Identity credentials, group memberships, sessions and consent cascade from the user.
        var result = await users.DeleteAsync(user);
        if (!result.Succeeded) throw new InvalidOperationException("Account deletion could not be completed.");
        await transaction.CommitAsync();
    }
}
