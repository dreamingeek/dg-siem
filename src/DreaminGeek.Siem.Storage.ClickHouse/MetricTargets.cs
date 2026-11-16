using ClickHouse.Driver;
using ClickHouse.Driver.ADO.Parameters;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

public enum TargetState
{
    Up,
    /// <summary>The last scrape failed.</summary>
    Down,
    /// <summary>No scrape for a while: the agent is offline, or the input was removed.</summary>
    Missing,
}

/// <summary>A scrape target (an agent's Prometheus input target) as its <c>up</c> series tells it.</summary>
/// <param name="Interval">How often it's scraped, from the last hour's samples; null with fewer than two.</param>
public sealed record MetricTarget(
    string Tenant, string Job, string Instance, DateTimeOffset LastScrape, bool Up, DateTimeOffset? LastUp,
    long? Samples, double? Seconds, TimeSpan? Interval)
{
    public string Key => $"metric|{Tenant}|{Job}|{Instance}";

    /// <summary>Missing after three intervals without a scrape (at least 5 minutes).</summary>
    public TimeSpan MissingAfter
    {
        get
        {
            var three = (Interval ?? TimeSpan.FromMinutes(1)) * 3;
            return three > TimeSpan.FromMinutes(5) ? three : TimeSpan.FromMinutes(5);
        }
    }

    public TargetState StateAt(DateTimeOffset now) =>
        now - LastScrape > MissingAfter ? TargetState.Missing : Up ? TargetState.Up : TargetState.Down;
}

/// <summary>Scrape targets seen in the last day, from the <c>up</c>, <c>scrape_samples_scraped</c> and <c>scrape_duration_seconds</c> series.</summary>
public sealed class MetricTargets(ClickHouseClient client, IOptions<ClickHouseOptions> options)
{
    public async Task<IReadOnlyList<MetricTarget>> GetAsync(IReadOnlyCollection<string> tenants, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        var sql =
            "SELECT tenant_id, labels['job'] AS job, labels['instance'] AS instance, " +
            "argMaxIf(value, timestamp, name = 'up') AS up, maxIf(timestamp, name = 'up') AS last, " +
            "maxIf(timestamp, name = 'up' AND value = 1) AS last_up, " +
            "argMaxIf(value, timestamp, name = 'scrape_samples_scraped') AS samples, countIf(name = 'scrape_samples_scraped') AS has_samples, " +
            "avgIf(value, name = 'scrape_duration_seconds' AND timestamp >= now() - INTERVAL 1 HOUR) AS secs, " +
            "countIf(name = 'up' AND timestamp >= now() - INTERVAL 1 HOUR) AS n, minIf(timestamp, name = 'up' AND timestamp >= now() - INTERVAL 1 HOUR) AS first " +
            $"FROM {options.Value.Database}.metrics " +
            "WHERE has({tenants:Array(String)}, tenant_id) AND name IN ('up', 'scrape_samples_scraped', 'scrape_duration_seconds') " +
            "AND timestamp >= now() - INTERVAL 1 DAY " +
            "GROUP BY tenant_id, job, instance HAVING countIf(name = 'up') > 0";
        var parameters = new ClickHouseParameterCollection
        {
            new ClickHouseDbParameter { ParameterName = "tenants", Value = tenants.ToArray(), ClickHouseType = "Array(String)" },
        };
        var targets = new List<MetricTarget>();
        await using var reader = await client.ExecuteReaderAsync(sql, parameters, new QueryOptions
        {
            MaxExecutionTime = TimeSpan.FromSeconds(30),
            CustomSettings = new Dictionary<string, object> { ["readonly"] = 2 },
        }, ct);
        while (await reader.ReadAsync(ct))
        {
            var last = Utc((DateTime)reader.GetValue(4));
            var lastUp = Utc((DateTime)reader.GetValue(5));
            var secs = Convert.ToDouble(reader.GetValue(8), System.Globalization.CultureInfo.InvariantCulture);
            var n = Convert.ToInt64(reader.GetValue(9), System.Globalization.CultureInfo.InvariantCulture);
            var first = Utc((DateTime)reader.GetValue(10));
            targets.Add(new MetricTarget(
                reader.GetString(0), reader.GetString(1), reader.GetString(2), last,
                Convert.ToDouble(reader.GetValue(3), System.Globalization.CultureInfo.InvariantCulture) >= 1,
                lastUp.Year > 1970 ? lastUp : null,
                Convert.ToInt64(reader.GetValue(7), System.Globalization.CultureInfo.InvariantCulture) > 0
                    ? (long)Convert.ToDouble(reader.GetValue(6), System.Globalization.CultureInfo.InvariantCulture) : null,
                double.IsNaN(secs) ? null : secs,
                n >= 2 ? (last - first) / (n - 1) : null));
        }
        return targets.OrderBy(t => t.Tenant, StringComparer.Ordinal).ThenBy(t => t.Job, StringComparer.Ordinal)
            .ThenBy(t => t.Instance, StringComparer.Ordinal).ToList();
    }

    private static DateTimeOffset Utc(DateTime d) => new(DateTime.SpecifyKind(d, DateTimeKind.Utc));
}
