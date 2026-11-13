using System.Globalization;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web.Agents;

namespace DreaminGeek.Siem.Web.Health;

/// <summary>
/// The health alert rules. Each finds everything wrong for one tenant and raises one alert listing it all, so an agent
/// going down sends one email, not one per source behind it. The alert's identity (for the quiet period) is the set of
/// things wrong: the same set stays quiet, and anything newly wrong alerts again.
/// </summary>
public sealed class HealthAlertSource(SourceActivity sources, AgentHealth agents, SettingsStore settings) : IHealthAlertSource
{
    /// <summary>A backlog this old on a checking-in agent means events aren't getting through.</summary>
    public static readonly TimeSpan StuckBacklog = TimeSpan.FromMinutes(30);

    public async Task<AlertEvaluation> EvaluateAsync(AlertRule rule, string tenant, DateTimeOffset now, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var zone = (await settings.GetGeneralAsync(ct)).Zone;
        return rule.Kind switch
        {
            AlertRuleKind.QuietSources => await QuietSourcesAsync(tenant, now, zone, ct),
            AlertRuleKind.AgentProblems => await AgentProblemsAsync(tenant, now, zone, ct),
            _ => throw new AlertRuleException($"{rule.Kind} isn't a health check."),
        };
    }

    private async Task<AlertEvaluation> QuietSourcesAsync(string tenant, DateTimeOffset now, TimeZoneInfo zone, CancellationToken ct)
    {
        var ignored = await settings.GetHealthAsync(ct);
        var quiet = (await sources.GetSourcesAsync([tenant], now, ct))
            .Where(s => s.State == SourceState.Quiet && !ignored.IsIgnored(s.Key)).ToList();
        string[] columns = ["source", "last event", "silent for", "usually silent at most"];
        var rows = quiet.Select(s => new object?[]
        {
            $"{s.Dataset} from {s.Host}", Local(s.LastSeen, zone), HealthText.Duration(s.SilentFor(now)), HealthText.UsualSilence(s.LongestSilence),
        }).ToList();
        var label = quiet.Count == 1 ? $"{quiet[0].Dataset} from {quiet[0].Host} went quiet" : $"{quiet.Count} sources went quiet";
        return Result(columns, rows, "quiet:" + string.Join(',', quiet.Select(s => s.Key).Order(StringComparer.Ordinal)), label);
    }

    private async Task<AlertEvaluation> AgentProblemsAsync(string tenant, DateTimeOffset now, TimeZoneInfo zone, CancellationToken ct)
    {
        var problems = new List<(string Agent, string Kind, object?[] Row)>();
        foreach (var a in await agents.ListAsync([tenant], ct))
        {
            if (a.State == AgentState.Revoked)
            {
                continue;
            }
            if (a.State == AgentState.Offline)
            {
                problems.Add((a.Name, "offline", [a.Name, "Not checking in", a.LastSeen is { } seen ? Local(seen, zone) : "never", a.Version ?? "?"]));
            }
            else if (a.Backlog is { OldestPending: { } oldest } backlog && oldest >= StuckBacklog)
            {
                problems.Add((a.Name, "backlog", [a.Name,
                    $"{HealthText.Bytes(backlog.PendingBytes)} waiting to be sent, oldest {HealthText.Duration(oldest)}",
                    a.LastSeen is { } seen ? Local(seen, zone) : "never", a.Version ?? "?"]));
            }
        }
        string[] columns = ["agent", "problem", "last check-in", "version"];
        var label = problems.Count == 1
            ? $"{problems[0].Agent} is {(problems[0].Kind == "offline" ? "offline" : "falling behind")}"
            : $"{problems.Count} agents need attention";
        return Result(columns, problems.Select(p => p.Row).ToList(),
            "agents:" + string.Join(',', problems.Select(p => $"{p.Agent}={p.Kind}").Order(StringComparer.Ordinal)), label);
    }

    private static AlertEvaluation Result(string[] columns, List<object?[]> rows, string key, string label) =>
        rows.Count == 0
            ? new AlertEvaluation(0, false, false, columns, [], [])
            : new AlertEvaluation(rows.Count, false, true, columns, rows, [new AlertGroup(key, label, rows)]);

    private static string Local(DateTimeOffset at, TimeZoneInfo zone) =>
        TimeZoneInfo.ConvertTime(at, zone).ToString("ddd d MMM HH:mm", CultureInfo.InvariantCulture);
}

public static class HealthText
{
    /// <summary>A source's longest normal silence, counted in whole empty hours.</summary>
    public static string UsualSilence(TimeSpan longest) => longest < TimeSpan.FromHours(1) ? "under an hour" : Duration(longest);

    public static string Duration(TimeSpan span) => span.TotalMinutes < 1 ? "under a minute"
        : span.TotalHours < 1 ? $"{(int)span.TotalMinutes} min"
        : span.TotalHours < 48 ? (span.Minutes >= 1 && span.TotalHours < 10 ? $"{(int)span.TotalHours} h {span.Minutes} min" : $"{(int)Math.Round(span.TotalHours)} h")
        : $"{(int)span.TotalDays} days";

    public static string Bytes(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / 1024d:0} KB",
        _ => $"{bytes} B",
    };
}
