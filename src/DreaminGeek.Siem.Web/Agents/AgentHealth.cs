using DreaminGeek.Siem.Data;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Agents;

public enum AgentState
{
    Online,
    Late,
    Offline,
    Revoked,
}

/// <param name="Backlog">What the agent last reported about its buffer (agents 0.5+, since the server started).</param>
public sealed record AgentStatus(
    Guid Id, string Tenant, string Name, string? Version, DateTimeOffset? LastSeen, DateTimeOffset? CertificateNotAfter, AgentState State,
    string? Platform = null, DreaminGeek.Siem.Core.Agents.AgentStatusReport? Backlog = null);

/// <summary>Agent check-in status for the overview and admin pages.</summary>
public sealed class AgentHealth(IDbContextFactory<SiemDbContext> dbFactory, AgentRegistry registry)
{
    // Agents poll config every minute and ship at least that often while logs flow.
    public static readonly TimeSpan OnlineWithin = TimeSpan.FromMinutes(3);
    public static readonly TimeSpan LateWithin = TimeSpan.FromMinutes(30);

    public async Task<IReadOnlyList<AgentStatus>> ListAsync(IReadOnlyCollection<string> tenants, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var rows = await db.Agents
            .Where(a => tenants.Contains(a.Tenant.Slug))
            .OrderBy(a => a.Tenant.Slug).ThenBy(a => a.Name)
            .Select(a => new { a.Id, Tenant = a.Tenant.Slug, a.Name, a.Version, a.LastSeenAt, a.CertificateNotAfter, a.RevokedAt, a.Platform })
            .ToListAsync(ct);
        var now = DateTimeOffset.UtcNow;
        return rows.Select(a => new AgentStatus(a.Id, a.Tenant, a.Name, a.Version, a.LastSeenAt, a.CertificateNotAfter,
            a.RevokedAt is not null ? AgentState.Revoked
            : a.LastSeenAt is { } seen && now - seen < OnlineWithin ? AgentState.Online
            : a.LastSeenAt is { } seen2 && now - seen2 < LateWithin ? AgentState.Late
            : AgentState.Offline, a.Platform, registry.GetStatus(a.Id)?.Report)).ToList();
    }

    public static string Ago(DateTimeOffset? when)
    {
        if (when is not { } t)
        {
            return "never";
        }
        var d = DateTimeOffset.UtcNow - t;
        return d.TotalSeconds < 60 ? "just now"
            : d.TotalMinutes < 60 ? $"{(int)d.TotalMinutes} min ago"
            : d.TotalHours < 48 ? $"{(int)d.TotalHours} h ago"
            : $"{(int)d.TotalDays} days ago";
    }
}
