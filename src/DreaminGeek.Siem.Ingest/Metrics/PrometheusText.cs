using System.Globalization;
using System.Text;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Ingest.Metrics;

/// <summary>
/// Reads the Prometheus text exposition format (and OpenMetrics text) as an agent shipped it, and adds what
/// Prometheus adds to every scrape: the <c>job</c> and <c>instance</c> labels and the <c>up</c>,
/// <c>scrape_duration_seconds</c> and <c>scrape_samples_scraped</c> series.
/// </summary>
public static class PrometheusText
{
    /// <summary>Most samples kept from one scrape; the rest are dropped (and <c>up</c> still says it worked).</summary>
    public const int MaxSamples = 200_000;
    private const int MaxLabels = 64;

    public static bool IsScrape(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return envelope.Input.StartsWith(MetricScrape.InputPrefix, StringComparison.Ordinal);
    }

    /// <summary>The samples in one scrape envelope. Lines that don't parse are skipped.</summary>
    public static List<MetricSample> Parse(RawEnvelope envelope, string tenantId) => Parse(envelope, tenantId, out _);

    /// <inheritdoc cref="Parse(RawEnvelope, string)"/>
    /// <param name="error">Why the scrape failed, as the agent reported it; null when it worked.</param>
    public static List<MetricSample> Parse(RawEnvelope envelope, string tenantId, out string? error)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var job = envelope.Input[MetricScrape.InputPrefix.Length..];
        var instance = envelope.SourceAddress ?? string.Empty;
        var at = envelope.ReceivedAt;
        var samples = new List<MetricSample>();
        var types = new Dictionary<string, string>(StringComparer.Ordinal);
        double? duration = null;
        error = null;

        foreach (var raw in envelope.Message.AsSpan().EnumerateLines())
        {
            var line = raw.Trim();
            if (line.IsEmpty)
            {
                continue;
            }
            if (line[0] == '#')
            {
                if (line.StartsWith(MetricScrape.HeaderPrefix, StringComparison.Ordinal))
                {
                    ReadHeader(line[MetricScrape.HeaderPrefix.Length..].Trim(), ref duration, ref error);
                }
                else if (line.StartsWith("# TYPE ", StringComparison.Ordinal))
                {
                    var rest = line[7..].Trim();
                    var space = rest.IndexOf(' ');
                    if (space > 0)
                    {
                        types[Unquote(rest[..space].ToString())] = rest[(space + 1)..].Trim().ToString().ToLowerInvariant();
                    }
                }
                continue;
            }
            if (error is null && samples.Count < MaxSamples && TryParseSample(line, out var name, out var labels, out var value, out var timestamp))
            {
                labels["job"] = labels.Remove("job", out var exportedJob) ? Exported(labels, "job", exportedJob, job) : job;
                labels["instance"] = labels.Remove("instance", out var exportedInstance) ? Exported(labels, "instance", exportedInstance, instance) : instance;
                samples.Add(new MetricSample(tenantId, timestamp ?? at, name, Sorted(labels), value, TypeOf(name, types)));
            }
        }

        // What Prometheus records about every scrape, so "is it up?" is a metric like any other.
        var scraped = samples.Count;
        var scrapeLabels = Sorted(new Dictionary<string, string>(StringComparer.Ordinal) { ["job"] = job, ["instance"] = instance });
        samples.Add(new MetricSample(tenantId, at, "up", scrapeLabels, error is null ? 1 : 0, "gauge"));
        if (duration is { } d)
        {
            samples.Add(new MetricSample(tenantId, at, "scrape_duration_seconds", scrapeLabels, d, "gauge"));
        }
        samples.Add(new MetricSample(tenantId, at, "scrape_samples_scraped", scrapeLabels, scraped, "gauge"));
        return samples;
    }

    /// <summary>A target's own job/instance label is kept as exported_job/exported_instance, as Prometheus does.</summary>
    private static string Exported(Dictionary<string, string> labels, string name, string targetValue, string scrapeValue)
    {
        labels["exported_" + name] = targetValue;
        return scrapeValue;
    }

    private static void ReadHeader(ReadOnlySpan<char> text, ref double? duration, ref string? error)
    {
        if (text.StartsWith("error=", StringComparison.Ordinal))
        {
            error = text[6..].ToString();
            return;
        }
        foreach (var part in text.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.StartsWith("duration_seconds=", StringComparison.Ordinal) &&
                double.TryParse(part.AsSpan(17), NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
            {
                duration = d;
            }
        }
    }

    /// <summary>The type of a sample's family: <c>x_bucket</c>, <c>x_sum</c>, <c>x_count</c> belong to histogram/summary <c>x</c>.</summary>
    private static string TypeOf(string name, Dictionary<string, string> types)
    {
        if (types.TryGetValue(name, out var type))
        {
            return type;
        }
        foreach (var suffix in (ReadOnlySpan<string>)["_bucket", "_sum", "_count", "_total", "_created", "_gcount", "_gsum"])
        {
            if (name.EndsWith(suffix, StringComparison.Ordinal) && types.TryGetValue(name[..^suffix.Length], out type))
            {
                return type;
            }
        }
        return "untyped";
    }

    /// <summary>
    /// <c>name{label="value",...} value [timestamp_ms]</c>, also with the name quoted inside the braces
    /// (<c>{"http.requests",code="200"}</c>, Prometheus 3) and an OpenMetrics exemplar after <c> # </c>.
    /// </summary>
    internal static bool TryParseSample(ReadOnlySpan<char> line, out string name, out Dictionary<string, string> labels, out double value, out DateTimeOffset? timestamp)
    {
        name = string.Empty;
        labels = new Dictionary<string, string>(StringComparer.Ordinal);
        value = 0;
        timestamp = null;
        var i = 0;

        // Metric name (may be absent here when it's quoted inside the braces).
        while (i < line.Length && IsNameChar(line[i], i == 0))
        {
            i++;
        }
        name = line[..i].ToString();

        if (i < line.Length && line[i] == '{')
        {
            i++;
            while (true)
            {
                SkipSpaces(line, ref i);
                if (i >= line.Length)
                {
                    return false;
                }
                if (line[i] == '}')
                {
                    i++;
                    break;
                }
                string key;
                if (line[i] == '"')
                {
                    if (!ReadQuoted(line, ref i, out key))
                    {
                        return false;
                    }
                }
                else
                {
                    var start = i;
                    while (i < line.Length && IsNameChar(line[i], i == start))
                    {
                        i++;
                    }
                    key = line[start..i].ToString();
                }
                SkipSpaces(line, ref i);
                if (i < line.Length && line[i] == '=')
                {
                    i++;
                    SkipSpaces(line, ref i);
                    if (i >= line.Length || line[i] != '"' || !ReadQuoted(line, ref i, out var labelValue))
                    {
                        return false;
                    }
                    if (key.Length > 0 && labels.Count < MaxLabels)
                    {
                        labels[key] = labelValue;
                    }
                }
                else if (name.Length == 0 && key.Length > 0)
                {
                    name = key; // {"metric.name", ...}
                }
                else
                {
                    return false;
                }
                SkipSpaces(line, ref i);
                if (i < line.Length && line[i] == ',')
                {
                    i++;
                }
            }
        }
        if (name.Length == 0)
        {
            return false;
        }

        // Value, optional timestamp, optional exemplar.
        var rest = line[i..].Trim();
        var exemplar = rest.IndexOf(" # ", StringComparison.Ordinal);
        if (exemplar >= 0)
        {
            rest = rest[..exemplar].TrimEnd();
        }
        var space = rest.IndexOf(' ');
        var valueText = space < 0 ? rest : rest[..space];
        if (!TryParseValue(valueText, out value) || double.IsNaN(value))
        {
            return false; // NaN: summaries with no observations, stale markers
        }
        if (space >= 0)
        {
            var tsText = rest[(space + 1)..].Trim();
            if (double.TryParse(tsText, NumberStyles.Float, CultureInfo.InvariantCulture, out var ts))
            {
                // Prometheus text: milliseconds; OpenMetrics: seconds (with a fraction).
                var ms = tsText.Contains('.') || ts < 100_000_000_000 ? ts * 1000 : ts;
                if (ms is > 0 and < 253_402_300_799_000)
                {
                    timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)ms);
                }
            }
        }
        return true;
    }

    private static bool TryParseValue(ReadOnlySpan<char> text, out double value)
    {
        switch (text)
        {
            case "+Inf" or "Inf" or "+inf" or "inf":
                value = double.PositiveInfinity;
                return true;
            case "-Inf" or "-inf":
                value = double.NegativeInfinity;
                return true;
            case "NaN" or "nan":
                value = double.NaN;
                return true;
            default:
                return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
        }
    }

    private static bool ReadQuoted(ReadOnlySpan<char> line, ref int i, out string text)
    {
        var sb = new StringBuilder();
        i++; // opening quote
        while (i < line.Length)
        {
            var c = line[i++];
            if (c == '"')
            {
                text = sb.ToString();
                return true;
            }
            if (c == '\\' && i < line.Length)
            {
                var e = line[i++];
                sb.Append(e switch { 'n' => '\n', _ => e });
            }
            else
            {
                sb.Append(c);
            }
        }
        text = string.Empty;
        return false;
    }

    private static string Unquote(string name) => name.Length >= 2 && name[0] == '"' && name[^1] == '"' ? name[1..^1] : name;

    private static void SkipSpaces(ReadOnlySpan<char> line, ref int i)
    {
        while (i < line.Length && line[i] is ' ' or '\t')
        {
            i++;
        }
    }

    private static bool IsNameChar(char c, bool first) =>
        char.IsAsciiLetter(c) || c is '_' or ':' || (!first && char.IsAsciiDigit(c));

    private static SortedDictionary<string, string> Sorted(Dictionary<string, string> labels) => new(labels, StringComparer.Ordinal);
}
