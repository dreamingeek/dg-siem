using System.Globalization;
using System.Text;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Ingest.Metrics;
using DreaminGeek.Siem.Parsers;

namespace DreaminGeek.Siem.Ingest.Otlp;

/// <summary>
/// Turns OTLP requests (as shipped by an agent's OTLP input) into events and metric samples.
/// <list type="bullet">
/// <item>Logs: each record's body goes through the parsers like any line (a Traefik JSON line sent through an
/// OpenTelemetry Collector still becomes <c>traefik.access</c>); one that nothing recognises gets the dataset
/// <c>otel.&lt;service&gt;</c>. The record's service, severity, trace and span ids and attributes become fields.</item>
/// <item>Metrics: named as OpenTelemetry's Prometheus exporter would (dots to underscores; histograms as
/// <c>_bucket</c>/<c>_count</c>/<c>_sum</c>), with <c>job</c> from the service and <c>instance</c> from the service
/// instance, host or sender, so <c>mstats</c> works on them like on scrapes.</item>
/// </list>
/// </summary>
public static class OtlpConvert
{
    public const int MaxRecords = 100_000;
    private const int MaxFields = 128;
    private const int MaxValueLength = 4096;

    /// <summary>Reads the envelope's logs; null when it isn't an OTLP logs envelope.</summary>
    public static List<LogEvent>? ToEvents(RawEnvelope envelope, string tenantId, ParserRegistry parsers)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(parsers);
        if (!OtlpPush.TryRead(envelope, out var signal, out var json, out var body) || signal != "logs")
        {
            return null;
        }
        var records = json ? OtlpJson.ReadLogs(body) : OtlpProtobuf.ReadLogs(body);
        var job = envelope.Input[OtlpPush.InputPrefix.Length..];
        var events = new List<LogEvent>(Math.Min(records.Count, MaxRecords));
        foreach (var record in records.Take(MaxRecords))
        {
            events.Add(ToEvent(record, envelope, tenantId, job, parsers));
        }
        return events;
    }

    private static LogEvent ToEvent(OtlpLogRecord record, RawEnvelope envelope, string tenantId, string job, ParserRegistry parsers)
    {
        var time = Time(record.TimeUnixNano) ?? Time(record.ObservedTimeUnixNano) ?? envelope.ReceivedAt;
        var text = record.Body ?? record.EventName ?? string.Empty;
        var resource = record.Resource.ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal);
        var attributes = record.Attributes.GroupBy(a => a.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Last().Value, StringComparer.Ordinal);
        var service = resource.GetValueOrDefault("service.name");

        var parsed = parsers.Parse(new RawEnvelope(time, envelope.Input, envelope.SourceAddress, text), tenantId);
        if (parsed.EventDataset == ParserRegistry.UnparsedDataset)
        {
            parsed.EventDataset = attributes.GetValueOrDefault("event.dataset") ?? resource.GetValueOrDefault("event.dataset") ?? Dataset(service);
            parsed.EventModule = "otel";
            parsed.Timestamp = time;
        }
        if (parsed.HostName.Length == 0)
        {
            parsed.HostName = resource.GetValueOrDefault("host.name") ?? resource.GetValueOrDefault("service.instance.id") ?? envelope.SourceAddress ?? string.Empty;
        }
        if (parsed.LogLevel.Length == 0)
        {
            parsed.LogLevel = Level(record.SeverityNumber, record.SeverityText);
        }

        void Add(string key, string? value)
        {
            if (!string.IsNullOrEmpty(value) && parsed.Fields.Count < MaxFields)
            {
                parsed.Fields.TryAdd(key, value.Length > MaxValueLength ? value[..MaxValueLength] : value);
            }
        }
        Add("otel.job", job);
        Add("trace.id", record.TraceId);
        Add("span.id", record.SpanId);
        Add("event.name", record.EventName);
        Add("otel.scope.name", record.Scope);
        if (record.SeverityNumber > 0)
        {
            Add("otel.severity_number", record.SeverityNumber.ToString(CultureInfo.InvariantCulture));
        }
        // Record attributes first: they're the most specific. The parser's own fields win over both.
        foreach (var (key, value) in attributes)
        {
            Add(key, value);
        }
        foreach (var (key, value) in resource)
        {
            Add(key, value);
        }
        return parsed;
    }

    /// <summary><c>otel.&lt;service&gt;</c>: lower-case letters, digits, dashes and underscores; <c>otel.logs</c> without a service.</summary>
    internal static string Dataset(string? service)
    {
        if (string.IsNullOrWhiteSpace(service))
        {
            return "otel.logs";
        }
        var sb = new StringBuilder("otel.");
        foreach (var c in service.Trim().ToLowerInvariant())
        {
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' ? c : '_');
            if (sb.Length >= 64)
            {
                break;
            }
        }
        return sb.ToString();
    }

    /// <summary>The severity text if there is one, else the severity number's level (1-4 trace ... 21-24 fatal).</summary>
    internal static string Level(int number, string? text)
    {
        if (!string.IsNullOrWhiteSpace(text))
        {
            return text.Trim().ToLowerInvariant() switch
            {
                "warning" => "warn",
                "information" => "info",
                "critical" => "fatal",
                var t => t,
            };
        }
        return number switch
        {
            >= 1 and <= 4 => "trace",
            >= 5 and <= 8 => "debug",
            >= 9 and <= 12 => "info",
            >= 13 and <= 16 => "warn",
            >= 17 and <= 20 => "error",
            >= 21 and <= 24 => "fatal",
            _ => string.Empty,
        };
    }

    /// <summary>Reads the envelope's metrics; null when it isn't an OTLP metrics envelope.</summary>
    public static List<MetricSample>? ToSamples(RawEnvelope envelope, string tenantId)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (!OtlpPush.TryRead(envelope, out var signal, out var json, out var body) || signal != "metrics")
        {
            return null;
        }
        var points = json ? OtlpJson.ReadMetrics(body) : OtlpProtobuf.ReadMetrics(body);
        var job = envelope.Input[OtlpPush.InputPrefix.Length..];
        var samples = new List<MetricSample>();
        foreach (var p in points)
        {
            if (samples.Count >= InfluxLineProtocol.MaxSamples || string.IsNullOrWhiteSpace(p.Name))
            {
                break;
            }
            AddSamples(p, tenantId, job, envelope, samples);
        }
        return samples;
    }

    private static void AddSamples(OtlpPoint p, string tenantId, string job, RawEnvelope envelope, List<MetricSample> samples)
    {
        var at = Time(p.TimeUnixNano) ?? envelope.ReceivedAt;
        var name = InfluxLineProtocol.Sanitize(p.Name);
        var labels = Labels(p, job, envelope.SourceAddress);
        void Add(string metric, double value, string type, string? extraKey = null, string? extraValue = null)
        {
            var l = labels;
            if (extraKey is not null)
            {
                l = new SortedDictionary<string, string>(labels, StringComparer.Ordinal) { [extraKey] = extraValue! };
            }
            samples.Add(new MetricSample(tenantId, at, metric, l, value, type));
        }

        switch (p.Kind)
        {
            case OtlpMetricKind.Gauge:
                Add(name, p.Value, "gauge");
                break;
            case OtlpMetricKind.Sum:
                // Cumulative monotonic sums are counters (rate() works on them); delta sums are per-interval amounts (use sum()).
                Add(name, p.Value, !p.Cumulative ? "untyped" : p.Monotonic ? "counter" : "gauge");
                break;
            case OtlpMetricKind.Histogram:
                ulong running = 0;
                for (var i = 0; i < p.BucketCounts.Count; i++)
                {
                    running += p.BucketCounts[i];
                    var le = i < p.ExplicitBounds.Count ? Bound(p.ExplicitBounds[i]) : "+Inf";
                    Add(name + "_bucket", running, "counter", "le", le);
                }
                Add(name + "_count", p.Count, "counter");
                if (p.Sum is { } hs)
                {
                    Add(name + "_sum", hs, "counter");
                }
                break;
            case OtlpMetricKind.ExponentialHistogram:
                Add(name + "_count", p.Count, "counter");
                if (p.Sum is { } es)
                {
                    Add(name + "_sum", es, "counter");
                }
                break;
            case OtlpMetricKind.Summary:
                foreach (var (quantile, value) in p.Quantiles)
                {
                    Add(name, value, "summary", "quantile", Bound(quantile));
                }
                Add(name + "_count", p.Count, "counter");
                if (p.Sum is { } ss)
                {
                    Add(name + "_sum", ss, "counter");
                }
                break;
        }
    }

    /// <summary>
    /// The point's attributes, plus <c>job</c> (service namespace/name, else the input's job) and <c>instance</c>
    /// (service instance id, else host name, else the sender), as OpenTelemetry's Prometheus conventions do.
    /// </summary>
    private static SortedDictionary<string, string> Labels(OtlpPoint p, string inputJob, string? sender)
    {
        var labels = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var a in p.Attributes.Take(64))
        {
            if (a.Key.Length > 0)
            {
                labels[InfluxLineProtocol.Sanitize(a.Key)] = a.Value;
            }
        }
        string? Resource(string key) => p.Resource.FirstOrDefault(a => a.Key == key).Value is { Length: > 0 } v ? v : null;
        var service = Resource("service.name");
        var ns = Resource("service.namespace");
        var job = service is null ? inputJob : ns is null ? service : $"{ns}/{service}";
        var instance = Resource("service.instance.id") ?? Resource("host.name") ?? sender ?? string.Empty;
        foreach (var (key, value) in new[] { ("job", job), ("instance", instance) })
        {
            if (labels.Remove(key, out var theirs))
            {
                labels["exported_" + key] = theirs;
            }
            labels[key] = value;
        }
        if (Resource("host.name") is { } host && !labels.ContainsKey("host_name"))
        {
            labels["host_name"] = host;
        }
        return labels;
    }

    private static string Bound(double value) =>
        double.IsPositiveInfinity(value) ? "+Inf" : double.IsNegativeInfinity(value) ? "-Inf" : value.ToString("R", CultureInfo.InvariantCulture);

    /// <summary>Nanoseconds since 1970 (64 bits reach the year 2554); null for 0, which OTLP uses for "not set".</summary>
    internal static DateTimeOffset? Time(ulong unixNano) =>
        unixNano > 0 ? DateTimeOffset.FromUnixTimeMilliseconds((long)(unixNano / 1_000_000)) : null;
}
