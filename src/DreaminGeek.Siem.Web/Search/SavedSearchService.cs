using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Web.Security;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Search;

/// <summary>Saved searches: each user sees their own; global admins see everyone's.</summary>
public sealed class SavedSearchService(IDbContextFactory<SiemDbContext> dbFactory)
{
    public async Task<IReadOnlyList<SavedSearch>> ListAsync(UserAccess access, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.SavedSearches
            .Where(s => access.IsGlobalAdmin || s.OwnerId == access.UserId)
            .OrderBy(s => s.Name)
            .ToListAsync(ct);
    }

    /// <summary>Saves, replacing the user's own search of the same name.</summary>
    public async Task SaveAsync(UserAccess access, string name, string query, string timeRange, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(access);
        name = name.Trim();
        if (name.Length is 0 or > 100)
        {
            throw new ArgumentException("Name must be 1-100 characters.", nameof(name));
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var existing = await db.SavedSearches.SingleOrDefaultAsync(s => s.OwnerId == access.UserId && s.Name == name, ct);
        if (existing is null)
        {
            db.SavedSearches.Add(new SavedSearch { Id = Guid.NewGuid(), Name = name, Query = query, TimeRange = timeRange, OwnerId = access.UserId });
        }
        else
        {
            existing.Query = query;
            existing.TimeRange = timeRange;
            existing.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(UserAccess access, Guid id, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(access);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.SavedSearches.Where(s => s.Id == id && (access.IsGlobalAdmin || s.OwnerId == access.UserId)).ExecuteDeleteAsync(ct);
    }
}
