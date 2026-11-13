using System.Globalization;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web.Agents;
using DreaminGeek.Siem.Web.Backups;
using DreaminGeek.Siem.Web.GeoIp;
using DreaminGeek.Siem.Web.Storage;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Health;

public enum CheckLevel
{
    Ok,
    Warn,
    Bad,

    /// <summary>Not set up (not a problem in itself).</summary>
    Off,
}

/// <param name="Link">Where to fix it.</param>
public sealed record HealthCheck(string Name, CheckLevel Level, string Detail, string? Link = null);

/// <param name="QuietAlert">The enabled quiet-source alert rule, if there is one.</param>
/// <param name="AgentAlert">The enabled agent alert rule, if there is one.</param>
/// <param name="SourcesAvailable">False when ClickHouse couldn't be asked about sources (so none are listed).</param>
public sealed record HealthReport(
    DateTimeOffset At, IReadOnlyList<HealthCheck> Checks, IReadOnlyList<SourceHealth> Sources, IReadOnlyList<AgentStatus> Agents,
    IReadOnlyList<IngestHour> Ingest, HealthSettings Settings, Guid? QuietAlert, Guid? AgentAlert, bool SourcesAvailable = true);

/// <summary>Administration &gt; Health: everything that has to work for logs to arrive, be kept, and raise alerts.</summary>
public sealed class HealthService(
    SourceActivity sources,
    AgentHealth agents,
    ClickHouseStorage storage,
    RetentionService retention,
    ColdStorageService coldStorage,
    BackupService backups,
    GeoIpUpdater geoIp,
    DreaminGeek.Siem.Web.ThreatIntel.ThreatIntelService threatIntel,
    DreaminGeek.Siem.Web.Features.FeatureState features,
    DreaminGeek.Siem.Ingest.IngestPipeline pipeline,
    SettingsStore settings,
    IDbContextFactory<SiemDbContext> dbFactory)
{
    /// <summary>With agents checking in, no event received for this long means ingest itself is stuck.</summary>
    public static readonly TimeSpan IngestStalled = TimeSpan.FromMinutes(15);

    public async Task<HealthReport> GetAsync(IReadOnlyCollection<string> tenants, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        var now = DateTimeOffset.UtcNow;
        var health = await settings.GetHealthAsync(ct);
        var agentList = await agents.ListAsync(tenants, ct);
        var checks = new List<HealthCheck>();

        IReadOnlyList<SourceHealth> sourceList = [];
        IReadOnlyList<IngestHour> ingest = [];
        var sourcesAvailable = true;
        try
        {
            sourceList = await sources.GetSourcesAsync(tenants, now, ct);
            ingest = await sources.GetIngestAsync(tenants, 48, ct);
            checks.Add(await EventStoreAsync(ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            sourcesAvailable = false;
            checks.Add(new("Event store", CheckLevel.Bad, $"ClickHouse isn't answering: {FirstLine(ex.Message)}"));
        }
        checks.Add(Ingest(pipeline.Status, sourceList, agentList, now));
        checks.Add(sourcesAvailable ? Sources(sourceList, health) : new("Log sources", CheckLevel.Off, "Can't check while ClickHouse isn't answering."));
        checks.Add(Agents(agentList, now));

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var rules = await db.AlertRules.AsNoTracking().Select(r => new { r.Id, r.Kind, r.Name, r.Enabled, r.LastError, r.EmailTo }).ToListAsync(ct);
        checks.Add(Alerts(rules.Select(r => (r.Name, r.Enabled, r.LastError)).ToList()));
        checks.Add(await EmailAsync(rules.Any(r => r.Enabled && !string.IsNullOrWhiteSpace(r.EmailTo)), ct));
        checks.Add(await BackupsAsync(now, ct));
        checks.Add(await ColdStorageAsync(ct));
        checks.Add(Certificates(agentList, now));
        checks.Add(GeoIp());
        if ((await features.GetAsync(ct)).ThreatIntel)
        {
            checks.Add(await ThreatIntelAsync(now, ct));
        }

        return new HealthReport(now, checks, sourceList, agentList, ingest, health,
            rules.FirstOrDefault(r => r.Kind == AlertRuleKind.QuietSources && r.Enabled)?.Id,
            rules.FirstOrDefault(r => r.Kind == AlertRuleKind.AgentProblems && r.Enabled)?.Id, sourcesAvailable);
    }

    /// <summary>Leaves a retired source out of quiet-source alerts (or puts it back).</summary>
    public async Task SetIgnoredAsync(string key, bool ignored, string by, CancellationToken ct)
    {
        var current = await settings.GetHealthAsync(ct);
        var rest = current.Ignored.Where(i => !string.Equals(i.Key, key, StringComparison.Ordinal)).ToList();
        if (ignored)
        {
            rest.Add(new IgnoredSource(key, DateTimeOffset.UtcNow, by));
        }
        await settings.SaveHealthAsync(current with { Ignored = rest }, ct);
    }

    private async Task<HealthCheck> EventStoreAsync(CancellationToken ct)
    {
        var status = await storage.GetStatusAsync(ct);
        var disk = status.Disks.FirstOrDefault(d => d.Name == "default");
        if (disk is null || disk.TotalBytes == 0)
        {
            return new("Event store", CheckLevel.Ok, "ClickHouse is answering.", "admin/storage");
        }
        var free = (double)disk.FreeBytes / disk.TotalBytes;
        var level = free < 0.08 ? CheckLevel.Bad : free < 0.15 ? CheckLevel.Warn : CheckLevel.Ok;
        var detail = $"ClickHouse is answering. {HealthText.Bytes(disk.FreeBytes)} free of {HealthText.Bytes(disk.TotalBytes)} on the event disk ({free * 100:0}%).";
        if (level != CheckLevel.Ok)
        {
            detail += status.TieredPolicyAvailable ? " Shorten retention or move events to the bucket sooner." : " Shorten retention or set up cold storage.";
        }
        return new("Event store", level, detail, "admin/storage");
    }

    private static HealthCheck Ingest(DreaminGeek.Siem.Ingest.IngestStatus status, IReadOnlyList<SourceHealth> sourceList, IReadOnlyList<AgentStatus> agentList, DateTimeOffset now)
    {
        if (status.FailingSince is { } since0)
        {
            return new("Ingest", CheckLevel.Bad,
                $"Can't write events to ClickHouse for {HealthText.Duration(now - since0)}: {status.LastError}. " +
                "Agents are keeping new events in their buffers and will send them when it's back.");
        }
        if (status.Queued > status.Capacity / 2)
        {
            return new("Ingest", CheckLevel.Warn,
                $"{status.Queued.ToString("N0", CultureInfo.InvariantCulture)} events are queued on the server waiting to be written; ClickHouse is falling behind.");
        }
        if (sourceList.Count == 0)
        {
            return new("Ingest", CheckLevel.Off, "No events received yet.", "admin/agents");
        }
        var newest = sourceList.Max(s => s.LastSeen);
        var day = sourceList.Sum(s => s.Events24h);
        var since = now - newest;
        var detail = $"Last event received {HealthText.Duration(since)} ago; {day.ToString("N0", CultureInfo.InvariantCulture)} in the last 24 hours.";
        return agentList.Any(a => a.State == AgentState.Online) && since > IngestStalled
            ? new("Ingest", CheckLevel.Bad, $"Agents are checking in, but nothing has been stored for {HealthText.Duration(since)}. Check the server's log.")
            : new("Ingest", CheckLevel.Ok, detail);
    }

    private static HealthCheck Sources(IReadOnlyList<SourceHealth> sourceList, HealthSettings health)
    {
        var watched = sourceList.Where(s => !health.IsIgnored(s.Key)).ToList();
        var quiet = watched.Where(s => s.State == SourceState.Quiet).ToList();
        var regular = watched.Count(s => s.State is SourceState.Active or SourceState.Quiet);
        var other = watched.Count - regular;
        var otherText = other > 0 ? $" ({other} new or occasional, not judged yet)" : string.Empty;
        return quiet.Count switch
        {
            0 when watched.Count == 0 => new("Log sources", CheckLevel.Off, "No sources yet."),
            0 => new("Log sources", CheckLevel.Ok, $"All {regular} regular sources are sending{otherText}."),
            _ => new("Log sources", CheckLevel.Warn,
                $"{quiet.Count} of {regular} regular sources went quiet: {string.Join(", ", quiet.Take(4).Select(s => $"{s.Dataset} from {s.Host} ({s.Tenant})"))}{(quiet.Count > 4 ? " and more" : "")}."),
        };
    }

    private static HealthCheck Agents(IReadOnlyList<AgentStatus> agentList, DateTimeOffset now)
    {
        var active = agentList.Where(a => a.State != AgentState.Revoked).ToList();
        if (active.Count == 0)
        {
            return new("Agents", CheckLevel.Off, "No agents enrolled.", "admin/agents");
        }
        var offline = active.Where(a => a.State == AgentState.Offline).ToList();
        var behind = active.Where(a => a.State != AgentState.Offline && a.Backlog?.OldestPending >= HealthAlertSource.StuckBacklog).ToList();
        var lost = active.Where(a => a.Backlog is { } b && b.Dropped + b.Evicted > 0).ToList();
        var problems = new List<string>();
        if (offline.Count > 0)
        {
            problems.Add($"{string.Join(", ", offline.Select(a => a.Name))} {(offline.Count == 1 ? "isn't" : "aren't")} checking in");
        }
        if (behind.Count > 0)
        {
            problems.Add($"{string.Join(", ", behind.Select(a => a.Name))} {(behind.Count == 1 ? "has" : "have")} events waiting over 30 minutes");
        }
        if (lost.Count > 0)
        {
            problems.Add($"{string.Join(", ", lost.Select(a => a.Name))} lost events since {(lost.Count == 1 ? "it" : "they")} started (buffer full)");
        }
        var online = active.Count(a => a.State == AgentState.Online);
        return problems.Count == 0
            ? new("Agents", CheckLevel.Ok, $"{online} of {active.Count} checking in, nothing waiting.", "admin/agents")
            : new("Agents", offline.Count > 0 ? CheckLevel.Bad : CheckLevel.Warn, string.Join("; ", problems) + ".", "admin/agents");
    }

    private static HealthCheck Alerts(List<(string Name, bool Enabled, string? LastError)> rules)
    {
        var enabled = rules.Where(r => r.Enabled).ToList();
        var failing = enabled.Where(r => r.LastError is not null).ToList();
        return enabled.Count == 0
            ? new("Alerts", CheckLevel.Off, "No alerts are on.", "alerts")
            : failing.Count == 0
                ? new("Alerts", CheckLevel.Ok, $"{enabled.Count} running without errors.", "alerts")
                : new("Alerts", CheckLevel.Warn, $"{failing.Count} failing on their last run: {string.Join(", ", failing.Take(3).Select(r => r.Name))}{(failing.Count > 3 ? " and more" : "")}.", "alerts");
    }

    private async Task<HealthCheck> EmailAsync(bool anyEmail, CancellationToken ct)
    {
        var smtp = await settings.GetSmtpAsync(ct);
        return smtp.IsConfigured
            ? new("Email", CheckLevel.Ok, $"Sending through {smtp.Host}.", "admin/notifications")
            : anyEmail
                ? new("Email", CheckLevel.Bad, "Alerts are set to email, but no mail server is set up.", "admin/notifications")
                : new("Email", CheckLevel.Off, "No mail server set up.", "admin/notifications");
    }

    private async Task<HealthCheck> BackupsAsync(DateTimeOffset now, CancellationToken ct)
    {
        var config = await backups.GetSettingsAsync(ct);
        var state = await backups.GetStateAsync(ct);
        var last = state.Runs.Count > 0 ? state.Runs[0] : null;
        var lastGood = state.Runs.FirstOrDefault(r => r.Error is null);
        if (!config.Enabled)
        {
            return new("Backups", CheckLevel.Warn, "Nightly backups are off.", "admin/backups");
        }
        if (last is null)
        {
            var problems = await backups.CheckAsync(config, ct);
            return new("Backups", problems.Count > 0 ? CheckLevel.Warn : CheckLevel.Off,
                problems.Count > 0 ? problems[0] : "No backup yet; the first runs tonight.", "admin/backups");
        }
        if (last.Error is not null)
        {
            return new("Backups", CheckLevel.Bad, $"The last backup failed: {last.Error}", "admin/backups");
        }
        var age = now - (lastGood?.StartedAt ?? DateTimeOffset.MinValue);
        return age > TimeSpan.FromHours(36)
            ? new("Backups", CheckLevel.Warn, $"The last good backup is {HealthText.Duration(age)} old.", "admin/backups")
            : new("Backups", CheckLevel.Ok,
                $"Last backup {HealthText.Duration(age)} ago{(last.Events is { } e ? $", events {HealthText.Bytes(e.Bytes)} ({(e.Full ? "full" : "differential")})" : "")}.", "admin/backups");
    }

    private async Task<HealthCheck> ColdStorageAsync(CancellationToken ct)
    {
        if (retention.Problem is { } problem)
        {
            return new("Cold storage", CheckLevel.Warn, problem, "admin/storage");
        }
        if (!retention.Current.ColdEnabled)
        {
            return new("Cold storage", CheckLevel.Off, "Not in use; events stay on the server's disk.", "admin/storage");
        }
        var status = await coldStorage.GetStatusAsync(ct);
        return new("Cold storage", CheckLevel.Ok,
            $"Events move to the bucket after {retention.Current.ColdAfterDays} days{(status.Endpoint is { } e ? $" ({e})" : "")}.", "admin/storage");
    }

    private static HealthCheck Certificates(IReadOnlyList<AgentStatus> agentList, DateTimeOffset now)
    {
        // Agents renew 30 days before expiry; one within 14 days of it has failed to renew.
        var expiring = agentList.Where(a => a.State != AgentState.Revoked && a.CertificateNotAfter is { } n && n - now < TimeSpan.FromDays(14)).ToList();
        return expiring.Count == 0
            ? new("Agent certificates", agentList.Count == 0 ? CheckLevel.Off : CheckLevel.Ok, agentList.Count == 0 ? "No agents enrolled." : "All renewing on time.", "admin/agents")
            : new("Agent certificates", CheckLevel.Bad,
                $"{string.Join(", ", expiring.Select(a => $"{a.Name} ({(a.CertificateNotAfter < now ? "expired" : $"expires in {HealthText.Duration(a.CertificateNotAfter!.Value - now)}")})"))}: renewal is failing. Check the agent's log.",
                "admin/agents");
    }

    private HealthCheck GeoIp()
    {
        var status = geoIp.Status;
        if (status.Databases.Count == 0)
        {
            return new("GeoIP", CheckLevel.Warn, status.LastError is { } e ? $"No database loaded: {FirstLine(e)}" : "No database loaded; addresses aren't getting countries.", "admin/geoip");
        }
        var built = status.Databases.Max(d => d.BuildDate);
        return status.LastError is { } error
            ? new("GeoIP", CheckLevel.Warn, $"Using a database from {built:d MMM yyyy}; the last update failed: {FirstLine(error)}", "admin/geoip")
            : new("GeoIP", CheckLevel.Ok, $"Database from {built:d MMM yyyy}.", "admin/geoip");
    }

    private async Task<HealthCheck> ThreatIntelAsync(DateTimeOffset now, CancellationToken ct)
    {
        var feeds = (await threatIntel.GetFeedsAsync(ct)).Where(f => f.Enabled).ToList();
        // A feed is stale when it has failed and its saved copy is more than three update intervals old (or there's none).
        var stale = feeds.Where(f => f.Error is not null && (f.Downloaded is null || now - f.Downloaded > 3 * f.Interval)).ToList();
        if (stale.Count > 0)
        {
            return new("Threat intel", CheckLevel.Warn,
                $"{string.Join("; ", stale.Select(f => $"{f.Name}: {f.Error}"))}{(stale.Any(f => f.Downloaded is not null) ? " Using older copies meanwhile." : "")}",
                "admin/threat-intel");
        }
        var loaded = feeds.Count(f => f.Entries > 0);
        return feeds.Count == 0
            ? new("Threat intel", CheckLevel.Warn, "On, but every feed is switched off.", "admin/threat-intel")
            : new("Threat intel", CheckLevel.Ok, loaded == 0 ? "On; the first downloads are under way." : $"{loaded} of {feeds.Count} feeds loaded and up to date.", "admin/threat-intel");
    }

    private static string FirstLine(string text)
    {
        var line = text.Split('\n', 2)[0].Trim();
        return line.Length > 300 ? line[..300] + "…" : line;
    }
}
