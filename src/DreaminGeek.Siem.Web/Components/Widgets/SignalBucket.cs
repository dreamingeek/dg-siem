namespace DreaminGeek.Siem.Web.Components.Widgets;

/// <summary>One time bucket of a <see cref="SignalStrip"/> (UTC start).</summary>
public readonly record struct SignalBucket(DateTime Start, long Count)
{
    /// <summary>Zero-filled buckets from <paramref name="from"/> to <paramref name="to"/>, aligned like ClickHouse's toStartOfInterval.</summary>
    public static List<SignalBucket> Fill(DateTimeOffset from, DateTimeOffset to, TimeSpan span, IReadOnlyDictionary<DateTime, long> counts)
    {
        ArgumentNullException.ThrowIfNull(counts);
        var ticks = span.Ticks;
        var start = new DateTime(from.UtcDateTime.Ticks / ticks * ticks, DateTimeKind.Utc);
        var buckets = new List<SignalBucket>();
        for (var t = start; t < to.UtcDateTime && buckets.Count < 2000; t = t.Add(span))
        {
            buckets.Add(new SignalBucket(t, counts.GetValueOrDefault(t)));
        }
        return buckets;
    }

    /// <summary>A sensible bucket size for a time range: about 24-120 bars.</summary>
    public static TimeSpan SpanFor(TimeSpan range) => range.TotalHours switch
    {
        <= 1 => TimeSpan.FromMinutes(1),
        <= 4 => TimeSpan.FromMinutes(5),
        <= 24 => TimeSpan.FromMinutes(15),
        <= 24 * 7 => TimeSpan.FromHours(2),
        <= 24 * 30 => TimeSpan.FromHours(6),
        _ => TimeSpan.FromDays(1),
    };

    /// <summary>Query-language span text, e.g. 15m, 2h, 1d.</summary>
    public static string SpanText(TimeSpan span) =>
        span.TotalDays >= 1 && span.TotalDays % 1 == 0 ? $"{(int)span.TotalDays}d"
        : span.TotalHours >= 1 && span.TotalHours % 1 == 0 ? $"{(int)span.TotalHours}h"
        : $"{(int)span.TotalMinutes}m";
}
