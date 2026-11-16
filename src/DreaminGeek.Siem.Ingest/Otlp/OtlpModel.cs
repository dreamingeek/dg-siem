namespace DreaminGeek.Siem.Ingest.Otlp;

/// <summary>An attribute with its value as text (arrays and maps as JSON).</summary>
public readonly record struct OtlpKeyValue(string Key, string Value);

/// <summary>One log record, with its resource's and scope's details.</summary>
public sealed class OtlpLogRecord
{
    public IReadOnlyList<OtlpKeyValue> Resource { get; set; } = [];
    public string? Scope { get; set; }
    public ulong TimeUnixNano { get; set; }
    public ulong ObservedTimeUnixNano { get; set; }
    public int SeverityNumber { get; set; }
    public string? SeverityText { get; set; }
    /// <summary>The body as text (a map or array body as JSON); null when there was none.</summary>
    public string? Body { get; set; }
    public List<OtlpKeyValue> Attributes { get; } = [];
    public string? TraceId { get; set; }
    public string? SpanId { get; set; }
    public string? EventName { get; set; }
}

public enum OtlpMetricKind
{
    Gauge,
    Sum,
    Histogram,
    ExponentialHistogram,
    Summary,
}

/// <summary>One data point of one metric, with its resource's details.</summary>
public sealed class OtlpPoint
{
    public IReadOnlyList<OtlpKeyValue> Resource { get; set; } = [];
    public string Name { get; set; } = string.Empty;
    public string? Unit { get; set; }
    public OtlpMetricKind Kind { get; set; }
    /// <summary>Sums: cumulative (true) or delta.</summary>
    public bool Cumulative { get; set; } = true;
    public bool Monotonic { get; set; }
    public ulong TimeUnixNano { get; set; }
    public List<OtlpKeyValue> Attributes { get; } = [];
    /// <summary>Gauges and sums.</summary>
    public double Value { get; set; }
    /// <summary>Histograms and summaries.</summary>
    public ulong Count { get; set; }
    public double? Sum { get; set; }
    public List<ulong> BucketCounts { get; } = [];
    public List<double> ExplicitBounds { get; } = [];
    public List<(double Quantile, double Value)> Quantiles { get; } = [];
}

/// <summary>A request that isn't valid OTLP.</summary>
public sealed class OtlpFormatException(string message) : Exception(message);
