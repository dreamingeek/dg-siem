using System.Security.Cryptography;
using System.Text.Json.Nodes;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Web.Admin;
using DreaminGeek.Siem.Web.Dashboards;
using DreaminGeek.Siem.Web.Search;
using DreaminGeek.Siem.Web.Security;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Integrations;

/// <summary>A pack as the Integrations page lists it.</summary>
public sealed record PackSummary(IntegrationPack Pack, int? InstalledVersion, IReadOnlyList<string> Tenants)
{
    public bool Installed => InstalledVersion is not null;
    public bool UpdateAvailable => InstalledVersion is { } v && v < Pack.Version;
}

/// <summary>Something a pack created, and whether it still matches what the pack wrote.</summary>
public sealed record PackItemView(string Kind, Guid Id, string Name, bool Edited, bool? Enabled);

/// <summary>One tenant's state for a pack.</summary>
public sealed record PackTenantView(string Slug, string Name, bool Enabled, string? Token, IReadOnlyList<(Guid Id, string Name, string? Version)> Agents);

public sealed record PackDetail(PackSummary Summary, IReadOnlyList<PackItemView> Items, IReadOnlyList<PackTenantView> Tenants);

/// <summary>What installing or updating a pack did.</summary>
/// <param name="Adopted">Your own dashboards and alerts with the pack's names (e.g. from the old ready-made lists), now the pack's.</param>
/// <param name="TurnedOnFor">Tenants the pack was turned on for on install, because they already send its data.</param>
public sealed record PackSyncReport(
    int Created, int Updated, int Removed, IReadOnlyList<string> KeptEdited,
    IReadOnlyList<string>? Adopted = null, IReadOnlyList<string>? TurnedOnFor = null);

/// <summary>Whether a tenant's data for a pack is arriving.</summary>
public sealed record PackReceivingStatus(bool Receiving, string Message);

/// <summary>
/// Installs integration packs (their dashboards and alerts, once for the server) and turns them on per tenant.
/// Global admins only, like dashboards and alerts.
/// </summary>
public sealed class IntegrationService(
    IDbContextFactory<SiemDbContext> dbFactory,
    PackCatalog catalog,
    TenantAccess access,
    AdminService admin,
    SearchService search)
{
    private const string Denied = "Only global admins can manage integrations.";

    public async Task<IReadOnlyList<PackSummary>> ListAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var installed = await db.InstalledPacks.AsNoTracking().ToDictionaryAsync(p => p.PackId, p => p.Version, ct);
        var enabled = (await db.TenantPacks.AsNoTracking().Select(p => new { p.PackId, p.Tenant.Slug }).ToListAsync(ct))
            .ToLookup(p => p.PackId, p => p.Slug);
        return catalog.Packs
            .Select(p => new PackSummary(p, installed.TryGetValue(p.Id, out var v) ? v : null, enabled[p.Id].Order(StringComparer.Ordinal).ToList()))
            .ToList();
    }

    public async Task<PackDetail?> GetAsync(UserAccess caller, string packId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        var pack = catalog.Find(packId);
        if (pack is null)
        {
            return null;
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var version = await db.InstalledPacks.AsNoTracking().Where(p => p.PackId == packId).Select(p => (int?)p.Version).FirstOrDefaultAsync(ct);
        var enabled = await db.TenantPacks.AsNoTracking().Where(p => p.PackId == packId).ToDictionaryAsync(p => p.TenantId, p => p.Token, ct);
        var agents = (await db.Agents.AsNoTracking().Where(a => a.RevokedAt == null).OrderBy(a => a.Name)
            .Select(a => new { a.TenantId, a.Id, a.Name, a.Version }).ToListAsync(ct)).ToLookup(a => a.TenantId);
        var tenants = (await db.Tenants.AsNoTracking().OrderBy(t => t.Slug).ToListAsync(ct))
            .Select(t => new PackTenantView(t.Slug, t.Name, enabled.ContainsKey(t.Id), enabled.GetValueOrDefault(t.Id),
                agents[t.Id].Select(a => (a.Id, a.Name, a.Version)).ToList()))
            .ToList();

        var items = new List<PackItemView>();
        foreach (var d in await db.Dashboards.AsNoTracking().Where(d => d.PackId == packId).OrderBy(d => d.Name).ToListAsync(ct))
        {
            items.Add(new PackItemView("Dashboard", d.Id, d.Name, !PackContent.Untouched(d), null));
        }
        foreach (var a in await db.AlertRules.AsNoTracking().Where(a => a.PackId == packId).OrderBy(a => a.Name).ToListAsync(ct))
        {
            items.Add(new PackItemView("Alert", a.Id, a.Name, !PackContent.Untouched(a), a.Enabled));
        }
        return new PackDetail(new PackSummary(pack, version, tenants.Where(t => t.Enabled).Select(t => t.Slug).ToList()), items, tenants);
    }

    /// <summary>
    /// Creates the pack's dashboards and alert rules (alerts switched off), or brings them up to the pack's
    /// current version. Anything someone edited since the pack wrote it is left as it is.
    /// </summary>
    public async Task<PackSyncReport> InstallAsync(UserAccess caller, string packId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        var pack = catalog.Find(packId) ?? throw new AdminException($"There's no integration pack \"{packId}\".");
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var report = await SyncAsync(db, pack, caller.UserId, ct);
        var installed = await db.InstalledPacks.FirstOrDefaultAsync(p => p.PackId == pack.Id, ct);
        List<string>? turnedOn = null;
        if (installed is null)
        {
            db.InstalledPacks.Add(new InstalledPack { PackId = pack.Id, Version = pack.Version });
            turnedOn = await TurnOnWhereReceivingAsync(db, pack, ct);
        }
        else
        {
            installed.Version = pack.Version;
            installed.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return report with { TurnedOnFor = turnedOn };
    }

    /// <summary>How far back a first install looks for a tenant's data, to turn the pack on for it.</summary>
    internal static readonly TimeSpan AutoEnableLookback = TimeSpan.FromDays(7);

    /// <summary>
    /// On first install, turns the pack on for every tenant that already sends its data (its "receiving" search
    /// over the last week). That keeps sources that were set up before the pack existed, and alerts adopted from
    /// the old ready-made list, running where they did.
    /// </summary>
    private async Task<List<string>> TurnOnWhereReceivingAsync(SiemDbContext db, IntegrationPack pack, CancellationToken ct)
    {
        var turnedOn = new List<string>();
        if (pack.Receiving is not { } receiving)
        {
            return turnedOn;
        }
        var already = await db.TenantPacks.Where(p => p.PackId == pack.Id).Select(p => p.TenantId).ToListAsync(ct);
        var now = DateTimeOffset.UtcNow;
        foreach (var tenant in await db.Tenants.AsNoTracking().Where(t => !already.Contains(t.Id)).OrderBy(t => t.Slug).ToListAsync(ct))
        {
            var result = await search.RunAsync(receiving.Search, now - AutoEnableLookback, now, [tenant.Slug], ct);
            if (result.Result is { Rows.Count: > 0 })
            {
                db.TenantPacks.Add(new TenantPack { TenantId = tenant.Id, PackId = pack.Id, Token = NeedsToken(pack) ? NewToken() : null });
                turnedOn.Add(tenant.Slug);
            }
        }
        return turnedOn;
    }

    /// <summary>
    /// Removes the pack from the server: turns it off for every tenant and deletes the dashboards and alerts it
    /// created, except edited ones, which stay as your own.
    /// </summary>
    public async Task<PackSyncReport> UninstallAsync(UserAccess caller, string packId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var removed = 0;
        var kept = new List<string>();
        foreach (var d in await db.Dashboards.Where(d => d.PackId == packId).ToListAsync(ct))
        {
            if (PackContent.Untouched(d))
            {
                db.Dashboards.Remove(d);
                removed++;
            }
            else
            {
                Detach(d);
                kept.Add(d.Name);
            }
        }
        foreach (var a in await db.AlertRules.Where(a => a.PackId == packId).ToListAsync(ct))
        {
            if (PackContent.Untouched(a))
            {
                db.AlertRules.Remove(a);
                removed++;
            }
            else
            {
                Detach(a);
                kept.Add(a.Name);
            }
        }
        await db.TenantPacks.Where(p => p.PackId == packId).ExecuteDeleteAsync(ct);
        await db.InstalledPacks.Where(p => p.PackId == packId).ExecuteDeleteAsync(ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return new PackSyncReport(0, 0, removed, kept);
    }

    /// <summary>Turns the pack on for a tenant (installing it first if needed) and gives the tenant its token.</summary>
    public async Task EnableAsync(UserAccess caller, string packId, string tenantSlug, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        var pack = catalog.Find(packId) ?? throw new AdminException($"There's no integration pack \"{packId}\".");
        await using (var check = await dbFactory.CreateDbContextAsync(ct))
        {
            if (!await check.InstalledPacks.AnyAsync(p => p.PackId == packId, ct))
            {
                await InstallAsync(caller, packId, ct);
            }
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Slug == tenantSlug, ct) ?? throw new AdminException($"Tenant \"{tenantSlug}\" doesn't exist.");
        if (await db.TenantPacks.AnyAsync(p => p.TenantId == tenant.Id && p.PackId == packId, ct))
        {
            return;
        }
        db.TenantPacks.Add(new TenantPack
        {
            TenantId = tenant.Id,
            PackId = packId,
            Token = NeedsToken(pack) ? NewToken() : null,
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Turns the pack off for a tenant: its alerts stop running there. Agent inputs are left alone.</summary>
    public async Task DisableAsync(UserAccess caller, string packId, string tenantSlug, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.TenantPacks.Where(p => p.PackId == packId && p.Tenant.Slug == tenantSlug).ExecuteDeleteAsync(ct);
    }

    /// <summary>
    /// Adds the pack's input to one of the tenant's agents. When the agent already has an input of that type on
    /// that port (every agent listens for syslog on 514), it's kept as it is, with the pack's token added to its
    /// tokens if the pack uses one. The agent's own checks apply (e.g. its version must support the input).
    /// </summary>
    /// <returns>What happened, for the page.</returns>
    public async Task<string> AddInputToAgentAsync(UserAccess caller, string packId, string tenantSlug, Guid agentId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        var pack = catalog.Find(packId) ?? throw new AdminException($"There's no integration pack \"{packId}\".");
        string? token;
        await using (var db = await dbFactory.CreateDbContextAsync(ct))
        {
            var row = await db.TenantPacks.AsNoTracking().FirstOrDefaultAsync(p => p.PackId == packId && p.Tenant.Slug == tenantSlug, ct)
                ?? throw new AdminException($"Turn the pack on for {tenantSlug} first.");
            token = row.Token;
            if (!await db.Agents.AnyAsync(a => a.Id == agentId && a.Tenant.Slug == tenantSlug, ct))
            {
                throw new AdminException($"That agent isn't one of {tenantSlug}'s.");
            }
        }
        var inputJson = PackContent.InputJson(pack, token ?? string.Empty) ?? throw new AdminException("This pack has no agent input to add.");
        var input = JsonNode.Parse(inputJson)!.AsObject();
        var config = JsonNode.Parse(await admin.GetAgentConfigJsonAsync(caller, agentId, ct))!.AsObject();
        var inputs = config["inputs"] as JsonArray ?? [];
        config["inputs"] = inputs;
        string Key(JsonNode? n) => $"{n?["type"]}|{n?["port"]}";
        var type = (string?)input["type"];
        var port = input["port"]?.ToString();
        var where = port is null ? type : $"{type} on port {port}";
        if (inputs.FirstOrDefault(n => string.Equals(Key(n), Key(input), StringComparison.OrdinalIgnoreCase)) is not JsonObject existing)
        {
            inputs.Add(input);
            await admin.SetAgentConfigAsync(caller, agentId, config.ToJsonString(), ct);
            return $"Added {where}.";
        }
        if (input["tokens"] is not JsonArray wanted || wanted.Count == 0)
        {
            return $"It already has {where}; nothing to change.";
        }
        var tokens = existing["tokens"] as JsonArray ?? [];
        existing["tokens"] = tokens;
        var have = tokens.Select(t => t?.ToString()).ToHashSet(StringComparer.Ordinal);
        var added = 0;
        foreach (var t in wanted.Select(t => t?.ToString()).Where(t => t is not null && !have.Contains(t)))
        {
            tokens.Add(t);
            added++;
        }
        if (added == 0)
        {
            return $"It already has {where} with this token; nothing to change.";
        }
        await admin.SetAgentConfigAsync(caller, agentId, config.ToJsonString(), ct);
        return $"It already had {where}; added this tenant's token to it.";
    }

    /// <summary>Runs the pack's "receiving" search for one tenant.</summary>
    public async Task<PackReceivingStatus?> ReceivingAsync(UserAccess caller, string packId, string tenantSlug, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, Denied, ct);
        if (catalog.Find(packId)?.Receiving is not { } receiving)
        {
            return null;
        }
        var within = DreaminGeek.Siem.Alerting.AlertEvaluator.ParseLookback(receiving.Within);
        var now = DateTimeOffset.UtcNow;
        var result = await search.RunAsync(receiving.Search, now - within, now, [tenantSlug], ct);
        var span = Describe(within);
        return result.Error is { } error
            ? new PackReceivingStatus(false, error)
            : result.Result is { Rows.Count: > 0 }
                ? new PackReceivingStatus(true, $"Receiving data (last {span})")
                : new PackReceivingStatus(false, $"Nothing in the last {span}");
    }

    /// <summary>"15 minutes", "hour", "2 hours", "day": reads after "the last".</summary>
    internal static string Describe(TimeSpan span) =>
        span.TotalDays >= 1 && span.TotalDays % 1 == 0 ? (span.TotalDays == 1 ? "day" : $"{span.TotalDays:0} days")
        : span.TotalHours >= 1 && span.TotalHours % 1 == 0 ? (span.TotalHours == 1 ? "hour" : $"{span.TotalHours:0} hours")
        : $"{span.TotalMinutes:0} minutes";

    internal static bool NeedsToken(IntegrationPack pack) =>
        pack.Setup.InputJson?.Contains("{{token}}", StringComparison.Ordinal) == true
        || pack.Setup.Steps.Any(s => s.Contains("{{token}}", StringComparison.Ordinal));

    /// <summary>32 random bytes, URL-safe base64 (43 characters): fits every input's token rules.</summary>
    internal static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Makes the database match the pack: creates what's missing, updates what nobody edited, removes what the
    /// pack dropped. A dashboard or alert of your own with the same name as one the pack makes (from the old
    /// ready-made lists, or made by hand) is adopted instead of duplicated; if it differs from the pack's, it
    /// counts as edited and stays as it is.
    /// </summary>
    internal static async Task<PackSyncReport> SyncAsync(SiemDbContext db, IntegrationPack pack, Guid owner, CancellationToken ct)
    {
        int created = 0, updated = 0, removed = 0;
        var kept = new List<string>();
        var adopted = new List<string>();

        var dashboards = await db.Dashboards.Where(d => d.PackId == pack.Id).ToListAsync(ct);
        var dashboardNames = await db.Dashboards.Select(d => d.Name).ToListAsync(ct);
        foreach (var source in pack.Dashboards)
        {
            var existing = dashboards.FirstOrDefault(d => d.PackItem == source.Key);
            if (existing is null && await db.Dashboards.FirstOrDefaultAsync(d => d.PackId == null && d.Name == source.Name.Trim(), ct) is { } mine)
            {
                var wanted = new Dashboard { Name = mine.Name };
                Apply(wanted, source);
                (mine.PackId, mine.PackItem, mine.PackHash) = (pack.Id, source.Key, PackContent.Hash(wanted));
                adopted.Add(mine.Name);
                continue;
            }
            if (existing is not null && !PackContent.Untouched(existing))
            {
                kept.Add(existing.Name);
                continue;
            }
            var target = existing ?? new Dashboard { Id = Guid.NewGuid(), Name = "", OwnerId = owner, PackId = pack.Id, PackItem = source.Key };
            var before = existing is null ? null : PackContent.Hash(existing);
            target.Name = existing is null ? UniqueName(source.Name, pack.Name, dashboardNames) : Rename(existing.Name, source.Name, pack.Name, dashboardNames);
            Apply(target, source);
            target.PackHash = PackContent.Hash(target);
            if (existing is null)
            {
                db.Dashboards.Add(target);
                dashboardNames.Add(target.Name);
                created++;
            }
            else if (before != target.PackHash)
            {
                target.UpdatedAt = DateTimeOffset.UtcNow;
                updated++;
            }
        }
        foreach (var gone in dashboards.Where(d => pack.Dashboards.All(s => s.Key != d.PackItem)))
        {
            if (PackContent.Untouched(gone))
            {
                db.Dashboards.Remove(gone);
                removed++;
            }
            else
            {
                Detach(gone);
            }
        }

        var alerts = await db.AlertRules.Where(a => a.PackId == pack.Id).ToListAsync(ct);
        var alertNames = await db.AlertRules.Select(a => a.Name).ToListAsync(ct);
        foreach (var source in pack.Alerts)
        {
            var existing = alerts.FirstOrDefault(a => a.PackItem == source.Key);
            if (existing is null && await db.AlertRules.FirstOrDefaultAsync(a => a.PackId == null && a.Kind == AlertRuleKind.Search && a.Name == source.Name.Trim(), ct) is { } mine)
            {
                // Keeps whether it's on, who it notifies and any tenant it was narrowed to.
                var wanted = new AlertRule { Name = mine.Name, Query = "" };
                Apply(wanted, source);
                (mine.PackId, mine.PackItem, mine.PackHash) = (pack.Id, source.Key, PackContent.Hash(wanted));
                adopted.Add(mine.Name);
                continue;
            }
            if (existing is not null && !PackContent.Untouched(existing))
            {
                kept.Add(existing.Name);
                continue;
            }
            // New alerts start switched off; on update, whether it's on, where it notifies and any tenant
            // it was narrowed to stay as they are.
            var target = existing ?? new AlertRule { Id = Guid.NewGuid(), Name = "", Query = "", Enabled = false, PackId = pack.Id, PackItem = source.Key };
            var before = existing?.PackHash;
            target.Name = existing is null ? UniqueName(source.Name, pack.Name, alertNames) : Rename(existing.Name, source.Name, pack.Name, alertNames);
            Apply(target, source);
            target.PackHash = PackContent.Hash(target);
            if (existing is null)
            {
                db.AlertRules.Add(target);
                alertNames.Add(target.Name);
                created++;
            }
            else if (before != target.PackHash)
            {
                target.UpdatedAt = DateTimeOffset.UtcNow;
                updated++;
            }
        }
        foreach (var gone in alerts.Where(a => pack.Alerts.All(s => s.Key != a.PackItem)))
        {
            if (PackContent.Untouched(gone))
            {
                db.AlertRules.Remove(gone);
                removed++;
            }
            else
            {
                Detach(gone);
            }
        }
        await db.SaveChangesAsync(ct);
        return new PackSyncReport(created, updated, removed, kept, adopted);
    }

    /// <summary>Everything but the name, which depends on what else exists.</summary>
    private static void Apply(Dashboard target, PackDashboard source)
    {
        target.Description = string.IsNullOrWhiteSpace(source.Description) ? null : source.Description.Trim();
        target.TimeRange = source.TimeRange;
        target.LayoutJson = PanelJson.Serialize(PackContent.Panels(source));
    }

    private static void Apply(AlertRule target, PackAlert source)
    {
        target.Kind = AlertRuleKind.Search;
        target.Description = string.IsNullOrWhiteSpace(source.Description) ? null : source.Description.Trim();
        target.Query = source.Search.Trim();
        target.TimeRange = "-" + source.TimeRange.Trim().TrimStart('-');
        target.Schedule = source.Schedule.Trim();
        target.Condition = PackContent.Condition(source.Condition);
        target.Threshold = source.Threshold;
        target.Trigger = PackContent.Trigger(source.Trigger);
        target.Severity = PackContent.Severity(source.Severity);
        target.SuppressBy = string.IsNullOrWhiteSpace(source.SuppressBy) ? null : source.SuppressBy.Trim();
        target.SuppressFor = TimeSpan.FromMinutes(source.SuppressMinutes);
    }

    /// <summary>
    /// The name an existing item keeps on update: unchanged if it's already the pack's name (or the pack's name with
    /// the suffix added for a clash), else the pack's new name, made unique.
    /// </summary>
    private static string Rename(string current, string wanted, string packName, List<string> taken)
    {
        wanted = wanted.Trim();
        if (current == wanted || current.StartsWith($"{wanted} ({packName}", StringComparison.Ordinal))
        {
            return current;
        }
        taken.Remove(current);
        var name = UniqueName(wanted, packName, taken);
        taken.Add(name);
        return name;
    }

    /// <summary>The pack's name for it, or with the pack's name added when that's taken by something else.</summary>
    private static string UniqueName(string name, string packName, List<string> taken)
    {
        name = name.Trim();
        if (!taken.Contains(name, StringComparer.Ordinal))
        {
            return name;
        }
        var candidate = $"{name} ({packName})";
        for (var n = 2; taken.Contains(candidate, StringComparer.Ordinal); n++)
        {
            candidate = $"{name} ({packName} {n})";
        }
        return candidate;
    }

    private static void Detach(Dashboard d) => (d.PackId, d.PackItem, d.PackHash) = (null, null, null);

    private static void Detach(AlertRule a) => (a.PackId, a.PackItem, a.PackHash) = (null, null, null);
}
