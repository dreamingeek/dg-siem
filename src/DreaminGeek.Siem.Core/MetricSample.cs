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

/// <summary>How agents ship pushed metrics (InfluxDB line protocol): one envelope per request or batch of datagrams.</summary>
public static class MetricPush
{
    /// <summary>Envelope input prefix; the rest is the input's job name (<c>influx:proxmox</c>).</summary>
    public const string InputPrefix = "influx:";

    /// <summary>First line of the message: <c># dgsiem_influx precision=ns</c> (ns, us, ms, s, or auto: guessed from the size).</summary>
    public const string HeaderPrefix = "# dgsiem_influx precision=";

    public static RawEnvelope Envelope(string? job, string? source, string precision, string lines) =>
        new(DateTimeOffset.UtcNow, InputPrefix + (string.IsNullOrWhiteSpace(job) ? "influxdb" : job), source, HeaderPrefix + precision + "\n" + lines);

    /// <summary>The <c>precision</c> query parameter (v1 also says h/m/u/n); null when it's not one InfluxDB accepts.</summary>
    public static string? Precision(string? value) => value switch
    {
        null or "" => "auto", // InfluxDB assumes ns; guessing also copes with senders that write seconds
        "ns" or "n" => "ns",
        "us" or "u" => "us",
        "ms" => "ms",
        "s" => "s",
        _ => null,
    };
}

/// <summary>
/// How agents ship OpenTelemetry (OTLP) requests: one envelope per request, the request's protobuf or JSON body
/// as it arrived (decompressed, base64 for protobuf) after a header line. The server decodes it (logs become events,
/// metrics become samples), so the agent stays simple and new OTLP features only need a server update.
/// </summary>
public static class OtlpPush
{
    /// <summary>Envelope input prefix; the rest is the input's job name (<c>otlp:otel</c>).</summary>
    public const string InputPrefix = "otlp:";

    /// <summary>First line: <c># dgsiem_otlp signal=logs encoding=protobuf</c> (signal logs or metrics; encoding protobuf or json).</summary>
    public const string HeaderPrefix = "# dgsiem_otlp ";

    public static RawEnvelope Envelope(string? job, string? source, string signal, bool json, ReadOnlySpan<byte> body) =>
        new(DateTimeOffset.UtcNow, InputPrefix + (string.IsNullOrWhiteSpace(job) ? "otel" : job), source,
            $"{HeaderPrefix}signal={signal} encoding={(json ? "json" : "protobuf")}\n" +
            (json ? System.Text.Encoding.UTF8.GetString(body) : Convert.ToBase64String(body)));

    public static bool IsOtlp(RawEnvelope envelope) =>
        envelope?.Input.StartsWith(InputPrefix, StringComparison.Ordinal) == true &&
        envelope.Message.StartsWith(HeaderPrefix, StringComparison.Ordinal);

    /// <summary>Reads an envelope back: the signal, whether it's JSON, and the body.</summary>
    public static bool TryRead(RawEnvelope envelope, out string signal, out bool json, out byte[] body)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        signal = string.Empty;
        json = false;
        body = [];
        var message = envelope.Message;
        var newline = message.IndexOf('\n', StringComparison.Ordinal);
        if (!IsOtlp(envelope) || newline < 0)
        {
            return false;
        }
        foreach (var part in message.AsSpan(HeaderPrefix.Length, newline - HeaderPrefix.Length).ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.StartsWith("signal=", StringComparison.Ordinal))
            {
                signal = part[7..];
            }
            else if (part == "encoding=json")
            {
                json = true;
            }
        }
        var payload = message.AsSpan(newline + 1);
        if (json)
        {
            body = System.Text.Encoding.UTF8.GetBytes(payload.ToString());
            return signal.Length > 0;
        }
        var bytes = new byte[payload.Length * 3 / 4 + 3];
        if (!Convert.TryFromBase64Chars(payload, bytes, out var written))
        {
            return false;
        }
        body = bytes[..written];
        return signal.Length > 0;
    }
}
