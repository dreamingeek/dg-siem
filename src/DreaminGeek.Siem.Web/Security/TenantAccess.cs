using System.Security.Claims;
using DreaminGeek.Siem.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace DreaminGeek.Siem.Web.Security;

/// <summary>What a signed-in user may see: every tenant (global admin) or their memberships.</summary>
public sealed record UserAccess(Guid UserId, bool IsGlobalAdmin, IReadOnlyList<string> Tenants)
{
    /// <summary>The server's admin CLI: shell access to the server already implies full control.</summary>
    public static UserAccess Shell { get; } = new(Guid.Empty, true, []) { IsShell = true };

    public bool IsShell { get; private init; }
}

/// <summary>
/// Resolves a user's tenants from PostgreSQL (cached 30s). This list is the only source of
/// <c>QueryRequest.TenantIds</c>; never take tenant lists from the client.
/// </summary>
public sealed class TenantAccess(IDbContextFactory<SiemDbContext> dbFactory, IMemoryCache cache)
{
    private static readonly TimeSpan CacheTime = TimeSpan.FromSeconds(30);

    public async Task<UserAccess?> GetAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId)
            ? await GetAsync(userId, ct)
            : null;
    }

    /// <summary>The user's current access (cached 30s, cleared when an admin changes it); null if deleted or locked.</summary>
    public async Task<UserAccess?> GetAsync(Guid userId, CancellationToken ct)
    {
        return await cache.GetOrCreateAsync("tenant-access:" + userId, async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheTime;
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var user = await db.Users.Where(u => u.Id == userId).Select(u => new { u.IsGlobalAdmin, u.LockoutEnd }).SingleOrDefaultAsync(ct);
            if (user is null || user.LockoutEnd > DateTimeOffset.UtcNow)
            {
                return null;
            }
            var tenants = user.IsGlobalAdmin
                ? await db.Tenants.OrderBy(t => t.Slug).Select(t => t.Slug).ToListAsync(ct)
                : await db.TenantMemberships.Where(m => m.UserId == userId).OrderBy(m => m.Tenant.Slug).Select(m => m.Tenant.Slug).ToListAsync(ct);
            return new UserAccess(userId, user.IsGlobalAdmin, tenants);
        });
    }

    /// <summary>The requested tenants narrowed to what the user may see. Empty request = all of them.</summary>
    public static IReadOnlyList<string> Narrow(UserAccess access, IEnumerable<string>? requested)
    {
        ArgumentNullException.ThrowIfNull(access);
        var wanted = requested?.Where(t => !string.IsNullOrWhiteSpace(t)).ToHashSet(StringComparer.Ordinal);
        return wanted is null || wanted.Count == 0 ? access.Tenants : access.Tenants.Where(wanted.Contains).ToList();
    }

    public void Forget(Guid userId) => cache.Remove("tenant-access:" + userId);

    /// <summary>
    /// Throws unless <paramref name="caller"/> is still a global admin. Re-reads their access rather than
    /// trusting what a page loaded when it opened, so a demoted, locked or deleted admin can't keep acting.
    /// Null (a page that hasn't loaded the user) is refused; the CLI passes <see cref="UserAccess.Shell"/>.
    /// </summary>
    public async Task RequireGlobalAdminAsync(UserAccess? caller, string message, CancellationToken ct)
    {
        if (caller?.IsShell == true)
        {
            return;
        }
        var current = caller is null || caller.UserId == Guid.Empty ? null : await GetAsync(caller.UserId, ct);
        if (current?.IsGlobalAdmin != true)
        {
            throw new Admin.AdminException(message);
        }
    }
}
