using ClickHouse.Driver;
using ClickHouse.Driver.ADO.Parameters;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

public enum SourceState
{
    /// <summary>Sending as usual.</summary>
    Active,

    /// <summary>Silent for longer than it usually is: worth a look.</summary>
    Quiet,

    /// <summary>First seen under two days ago: no baseline yet, so never quiet.</summary>
    New,

    /// <summary>Sends now and then (under a day's worth of hours in its week): too irregular to call quiet.</summary>
    Irregular,
}

/// <summary>
/// A source: one tenant's host (host.name, or the sending device's address) sending one dataset.
/// <paramref name="LongestSilence"/> is the longest the source went without events in its last 8 days of activity,
/// and <paramref name="QuietAfter"/> how long a silence must last before it counts as quiet.
/// </summary>
public sealed record SourceHealth(
    string Tenant, string Dataset, string Host, DateTimeOffset FirstSeen, DateTimeOffset LastSeen,
    long Events24h, double UsualPerDay, int ActiveHours, TimeSpan LongestSilence, TimeSpan QuietAfter, SourceState State)
{
    public string Key => $"{Tenant}|{Dataset}|{Host}";

    public TimeSpan SilentFor(DateTimeOffset now) => now - LastSeen;
}

/// <summary>An hour of ingest: events received across the given tenants.</summary>
public sealed record IngestHour(DateTimeOffset Hour, string Tenant, long Events, long Bytes);

/// <summary>
/// Reads the hourly <c>source_activity</c> rollup (migration 005) and judges each source against its own pattern:
/// a firewall that logs every hour is quiet after a couple of silent hours, a PBX that's silent every night only after
/// it misses a whole night and more.
/// </summary>
public sealed class SourceActivity(ClickHouseClient client, IOptions<ClickHouseOptions> options)
{
    /// <summary>
    /// Days of activity a source's baseline looks at: 8, so a weekly pattern's gap (a quiet weekend) falls inside the
    /// window whole rather than straddling its start.
    /// </summary>
    public const int BaselineDays = 8;

    /// <summary>Hours with events a source needs in its baseline to be judged; fewer is <see cref="SourceState.Irregular"/>.</summary>
    public const int MinActiveHours = 24;

    public static readonly TimeSpan NewFor = TimeSpan.FromDays(2);
    public static readonly TimeSpan MinQuietAfter = TimeSpan.FromHours(2);
    public static readonly TimeSpan MaxQuietAfter = TimeSpan.FromHours(72);

    private string Db => options.Value.Database;

    /// <summary>Every source of <paramref name="tenants"/> seen in the last 35 days, judged at <paramref name="now"/>.</summary>
    public async Task<IReadOnlyList<SourceHealth>> GetSourcesAsync(IReadOnlyCollection<string> tenants, DateTimeOffset now, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        var sql =
            "SELECT tenant_id, event_dataset, host, groupArray(hour), groupArray(events), max(last) " +
            "FROM (SELECT tenant_id, event_dataset, host, hour, toInt64(sum(events)) AS events, max(last_seen) AS last " +
            $"      FROM {Db}.source_activity WHERE has({{tenants:Array(String)}}, tenant_id) GROUP BY tenant_id, event_dataset, host, hour) " +
            "GROUP BY tenant_id, event_dataset, host";
        var parameters = new ClickHouseParameterCollection
        {
            new ClickHouseDbParameter { ParameterName = "tenants", Value = tenants.ToArray(), ClickHouseType = "Array(String)" },
        };
        var sources = new List<SourceHealth>();
        await using var reader = await client.ExecuteReaderAsync(sql, parameters, ReadOnly(), ct);
        while (await reader.ReadAsync(ct))
        {
            var hours = ((IEnumerable<DateTime>)reader.GetValue(3)).Select(Utc).ToArray();
            var counts = ((IEnumerable<long>)reader.GetValue(4)).ToArray();
            var activity = new Dictionary<DateTimeOffset, long>(hours.Length);
            for (var i = 0; i < hours.Length; i++)
            {
                activity[hours[i]] = counts[i];
            }
            sources.Add(Evaluate(reader.GetString(0), reader.GetString(1), reader.GetString(2), activity, Utc((DateTime)reader.GetValue(5)), now));
        }
        return sources.OrderBy(s => s.State == SourceState.Quiet ? 0 : 1).ThenBy(s => s.Tenant, StringComparer.Ordinal)
            .ThenBy(s => s.Dataset, StringComparer.Ordinal).ThenBy(s => s.Host, StringComparer.Ordinal).ToList();
    }

    /// <summary>Events received per hour and tenant over the last <paramref name="hours"/> hours.</summary>
    public async Task<IReadOnlyList<IngestHour>> GetIngestAsync(IReadOnlyCollection<string> tenants, int hours, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        var sql = $"SELECT hour, tenant_id, toInt64(sum(events)), toInt64(sum(bytes)) FROM {Db}.source_activity " +
                  "WHERE has({tenants:Array(String)}, tenant_id) AND hour >= toStartOfHour(now()) - toIntervalHour({hours:UInt16}) " +
                  "GROUP BY hour, tenant_id ORDER BY hour, tenant_id";
        var parameters = new ClickHouseParameterCollection
        {
            new ClickHouseDbParameter { ParameterName = "tenants", Value = tenants.ToArray(), ClickHouseType = "Array(String)" },
            new ClickHouseDbParameter { ParameterName = "hours", Value = (ushort)hours, ClickHouseType = "UInt16" },
        };
        var rows = new List<IngestHour>();
        await using var reader = await client.ExecuteReaderAsync(sql, parameters, ReadOnly(), ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new IngestHour(Utc((DateTime)reader.GetValue(0)), reader.GetString(1), reader.GetInt64(2), reader.GetInt64(3)));
        }
        return rows;
    }

    /// <summary>
    /// Judges one source from its hourly activity (hour → events). The baseline is the 8 days up to the source's last
    /// event, so a source that stopped long ago stays quiet rather than fading into "irregular".
    /// </summary>
    public static SourceHealth Evaluate(
        string tenant, string dataset, string host, IReadOnlyDictionary<DateTimeOffset, long> activity, DateTimeOffset lastSeen, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(activity);
        var first = activity.Count == 0 ? lastSeen : activity.Keys.Min();
        var lastHour = Hour(lastSeen);
        var windowStart = lastHour.AddDays(-BaselineDays).AddHours(1);
        var active = activity.Where(a => a.Key >= windowStart && a.Key <= lastHour && a.Value > 0).Select(a => a.Key).Order().ToList();

        // Longest run of empty hours between two active hours in the window.
        var longest = 0;
        for (var i = 1; i < active.Count; i++)
        {
            longest = Math.Max(longest, (int)(active[i] - active[i - 1]).TotalHours - 1);
        }
        var silence = TimeSpan.FromHours(longest);
        // Twice the usual longest silence, plus slack for hourly buckets (an event at 10:01 and the next at 11:59
        // leaves no empty hour but nearly two hours of silence).
        var quietAfter = TimeSpan.FromHours(Math.Clamp(2 * (longest + 1), MinQuietAfter.TotalHours, MaxQuietAfter.TotalHours));

        // Volume: the last 24 hours against the average day of the week before.
        var dayAgo = Hour(now.AddDays(-1));
        var events24h = activity.Where(a => a.Key > dayAgo).Sum(a => a.Value);
        var weekBefore = activity.Where(a => a.Key > dayAgo.AddDays(-7) && a.Key <= dayAgo).Sum(a => a.Value);
        var observedDays = Math.Clamp(((dayAgo - Hour(first)).TotalHours + 1) / 24, 0, 7);
        var usualPerDay = observedDays >= 1 ? weekBefore / observedDays : 0;

        var state = now - first < NewFor ? SourceState.New
            : active.Count < MinActiveHours ? SourceState.Irregular
            : now - lastSeen > quietAfter ? SourceState.Quiet
            : SourceState.Active;
        return new SourceHealth(tenant, dataset, host, first, lastSeen, events24h, usualPerDay, active.Count, silence, quietAfter, state);
    }

    private static DateTimeOffset Hour(DateTimeOffset t)
    {
        var u = t.UtcDateTime;
        return new DateTimeOffset(u.Year, u.Month, u.Day, u.Hour, 0, 0, TimeSpan.Zero);
    }

    private static DateTimeOffset Utc(DateTime d) => new(DateTime.SpecifyKind(d, DateTimeKind.Utc));

    private static QueryOptions ReadOnly() => new()
    {
        MaxExecutionTime = TimeSpan.FromSeconds(60),
        CustomSettings = new Dictionary<string, object> { ["readonly"] = 2 },
    };
}
