using System.Collections.Concurrent;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Ingest;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Agents;

/// <summary>Loads enabled drop rules from PostgreSQL every 30s and persists drop counters.</summary>
public sealed partial class DbDropRuleSource(IDbContextFactory<SiemDbContext> dbFactory, ILogger<DbDropRuleSource> logger)
    : BackgroundService, IDropRuleSource
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<Guid, long> _pending = new();
    private volatile IReadOnlyList<DropRule> _rules = [];

    public IReadOnlyList<DropRule> Current => _rules;

    public void Report(IReadOnlyDictionary<Guid, long> droppedByRule)
    {
        ArgumentNullException.ThrowIfNull(droppedByRule);
        foreach (var (id, n) in droppedByRule)
        {
            _pending.AddOrUpdate(id, n, (_, existing) => existing + n);
        }
    }

    public async Task ReloadAsync(CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var rows = await db.DropRules.Where(r => r.Enabled)
            .Select(r => new { r.Id, r.Name, Tenant = r.Tenant == null ? null : r.Tenant.Slug, r.Dataset, r.Field, r.Match, r.Value })
            .ToListAsync(ct);
        _rules = rows.Select(r => new DropRule(r.Id, r.Name, r.Tenant, r.Dataset, r.Field, ParseMatch(r.Match), r.Value)).ToArray();
    }

    public static DropMatch ParseMatch(string match) =>
        Enum.TryParse<DropMatch>(match, ignoreCase: true, out var m) ? m : DropMatch.Any;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PersistCountersAsync(stoppingToken);
                await ReloadAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is DbUpdateException or Npgsql.NpgsqlException or InvalidOperationException)
            {
                LogReloadFailed(logger, ex);
            }
            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task PersistCountersAsync(CancellationToken ct)
    {
        if (_pending.IsEmpty)
        {
            return;
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var now = DateTimeOffset.UtcNow;
        foreach (var id in _pending.Keys)
        {
            if (_pending.TryRemove(id, out var n))
            {
                await db.DropRules.Where(r => r.Id == id).ExecuteUpdateAsync(s => s
                    .SetProperty(r => r.DroppedTotal, r => r.DroppedTotal + n)
                    .SetProperty(r => r.LastDroppedAt, now), ct);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not refresh drop rules; keeping the current set")]
    private static partial void LogReloadFailed(ILogger logger, Exception ex);
}
