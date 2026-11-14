namespace DreaminGeek.Siem.Core;

/// <summary>One metric value at one time: a Prometheus sample, with the scrape's <c>job</c> and <c>instance</c> labels.</summary>
/// <param name="Name">Metric name, e.g. <c>node_load1</c>.</param>
/// <param name="Labels">Labels, sorted by name; together with <paramref name="Name"/> they identify the series.</param>
/// <param name="Type">counter, gauge, histogram, summary or untyped (from the exposition's <c># TYPE</c>).</param>
public sealed record MetricSample(
    string TenantId,
    DateTimeOffset Timestamp,
    string Name,
    IReadOnlyDictionary<string, string> Labels,
    double Value,
    string Type);

/// <summary>Writes metric samples to the metrics store.</summary>
public interface IMetricSink
{
    Task WriteAsync(IReadOnlyList<MetricSample> batch, CancellationToken cancellationToken);
}

/// <summary>How agents ship a Prometheus scrape: one envelope per target and scrape.</summary>
public static class MetricScrape
{
    /// <summary>Envelope input prefix; the rest is the job name (<c>prometheus:netprox</c>).</summary>
    public const string InputPrefix = "prometheus:";

    /// <summary>
    /// First line of the envelope's message, before the exposition text:
    /// <c># dgsiem_scrape duration_seconds=0.042</c>, or <c># dgsiem_scrape error=...</c> when the scrape failed.
    /// A comment, so the rest is plain Prometheus text.
    /// </summary>
    public const string HeaderPrefix = "# dgsiem_scrape ";

    /// <summary>The most an agent ships for one scrape (exposition text); bigger pages count as a failed scrape.</summary>
    public const int MaxBytes = 8 * 1024 * 1024;

    /// <summary>A Prometheus-style duration: <c>500ms</c>, <c>15s</c>, <c>1m</c>, <c>2h</c>.</summary>
    public static bool TryParseDuration(string? text, out TimeSpan duration)
    {
        duration = default;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }
        var unitLength = text.EndsWith("ms", StringComparison.Ordinal) ? 2 : 1;
        if (text.Length <= unitLength ||
            !int.TryParse(text.AsSpan(0, text.Length - unitLength), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n))
        {
            return false;
        }
        TimeSpan? parsed = text[^unitLength..] switch
        {
            "ms" => TimeSpan.FromMilliseconds(n),
            "s" => TimeSpan.FromSeconds(n),
            "m" => TimeSpan.FromMinutes(n),
            "h" => TimeSpan.FromHours(n),
            _ => null,
        };
        duration = parsed ?? default;
        return parsed is not null;
    }
}
