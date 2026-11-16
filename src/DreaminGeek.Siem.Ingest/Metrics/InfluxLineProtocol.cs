using System.Globalization;
using System.Text;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Ingest.Metrics;

/// <summary>
/// Reads InfluxDB line protocol (<c>measurement,tag=v field=1.5,other=3i 1731585600000000000</c>) into metric samples,
/// named the way Telegraf and VictoriaMetrics name them for Prometheus: <c>measurement_field</c>, with the tags as
/// labels. String fields are skipped; booleans become 1 or 0. The input's <c>job</c> and the sender's address
/// (<c>instance</c>) are added, as for scrapes.
/// </summary>
public static class InfluxLineProtocol
{
    public const int MaxSamples = 200_000;

    public static bool IsPush(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return envelope.Input.StartsWith(MetricPush.InputPrefix, StringComparison.Ordinal);
    }

    public static List<MetricSample> Parse(RawEnvelope envelope, string tenantId)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var job = envelope.Input[MetricPush.InputPrefix.Length..];
        var instance = envelope.SourceAddress ?? string.Empty;
        var precision = "auto";
        var samples = new List<MetricSample>();
        foreach (var raw in envelope.Message.AsSpan().EnumerateLines())
        {
            var line = raw.Trim();
            if (line.IsEmpty)
            {
                continue;
            }
            if (line[0] == '#')
            {
                if (line.StartsWith(MetricPush.HeaderPrefix, StringComparison.Ordinal))
                {
                    precision = line[MetricPush.HeaderPrefix.Length..].Trim().ToString();
                }
                continue;
            }
            if (samples.Count >= MaxSamples)
            {
                break;
            }
            ParseLine(line, tenantId, job, instance, precision, envelope.ReceivedAt, samples);
        }
        return samples;
    }

    /// <summary>One line into its samples (one per numeric field). A line that doesn't parse adds nothing.</summary>
    internal static void ParseLine(ReadOnlySpan<char> line, string tenantId, string job, string instance, string precision,
        DateTimeOffset received, List<MetricSample> samples)
    {
        var i = 0;
        var measurement = ReadUntil(line, ref i, ',', ' ', '\0');
        if (measurement.Length == 0)
        {
            return;
        }
        var labels = new Dictionary<string, string>(StringComparer.Ordinal);
        while (i < line.Length && line[i] == ',')
        {
            i++;
            var key = ReadUntil(line, ref i, '=', ',', ' ');
            if (i >= line.Length || line[i] != '=')
            {
                return;
            }
            i++;
            var value = ReadUntil(line, ref i, ',', ' ', '\0');
            if (key.Length > 0 && value.Length > 0 && labels.Count < 64)
            {
                labels[Sanitize(key)] = value;
            }
        }
        SkipSpaces(line, ref i);

        var fields = new List<(string Name, double Value)>();
        while (i < line.Length)
        {
            var key = ReadUntil(line, ref i, '=', ',', ' ');
            if (i >= line.Length || line[i] != '=' || key.Length == 0)
            {
                return;
            }
            i++;
            if (i < line.Length && line[i] == '"')
            {
                if (!SkipQuoted(line, ref i))
                {
                    return; // unterminated string: the rest of the line can't be trusted
                }
            }
            else
            {
                var text = ReadUntil(line, ref i, ',', ' ', '\0');
                if (TryNumber(text, out var number))
                {
                    fields.Add((key, number));
                }
            }
            if (i < line.Length && line[i] == ',')
            {
                i++;
                continue;
            }
            break;
        }
        if (fields.Count == 0)
        {
            return;
        }
        SkipSpaces(line, ref i);
        var at = received;
        if (i < line.Length && long.TryParse(line[i..].Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var ts))
        {
            at = Timestamp(ts, precision) ?? received;
        }

        labels["job"] = labels.Remove("job", out var exportedJob) ? Exported(labels, "job", exportedJob, job) : job;
        labels["instance"] = labels.Remove("instance", out var exportedInstance) ? Exported(labels, "instance", exportedInstance, instance) : instance;
        var sorted = new SortedDictionary<string, string>(labels, StringComparer.Ordinal);
        var prefix = Sanitize(measurement);
        foreach (var (name, value) in fields)
        {
            samples.Add(new MetricSample(tenantId, at, prefix + "_" + Sanitize(name), sorted, value, "untyped"));
        }
    }

    private static string Exported(Dictionary<string, string> labels, string name, string sent, string ours)
    {
        labels["exported_" + name] = sent;
        return ours;
    }

    /// <summary>A timestamp in the given precision; "auto" goes by its size (seconds, ms, µs or ns since 1970).</summary>
    public static DateTimeOffset? Timestamp(long value, string precision)
    {
        if (value <= 0)
        {
            return null;
        }
        var unit = precision switch
        {
            "s" or "ms" or "us" or "ns" => precision,
            _ => value switch
            {
                < 100_000_000_000L => "s",
                < 100_000_000_000_000L => "ms",
                < 100_000_000_000_000_000L => "us",
                _ => "ns",
            },
        };
        long ms = unit switch
        {
            "s" => value <= long.MaxValue / 1000 ? value * 1000 : -1,
            "ms" => value,
            "us" => value / 1000,
            _ => value / 1_000_000,
        };
        return ms is > 0 and < 253_402_300_799_000 ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null;
    }

    /// <summary>Integers (<c>3i</c>, <c>3u</c>), floats and booleans; strings were skipped before this.</summary>
    internal static bool TryNumber(string text, out double value)
    {
        value = 0;
        switch (text)
        {
            case "t" or "T" or "true" or "True" or "TRUE":
                value = 1;
                return true;
            case "f" or "F" or "false" or "False" or "FALSE":
                return true;
        }
        var span = text.AsSpan();
        if (span.Length > 1 && span[^1] is 'i' or 'u')
        {
            span = span[..^1];
        }
        return double.TryParse(span, NumberStyles.Float, CultureInfo.InvariantCulture, out value) && double.IsFinite(value);
    }

    /// <summary>Reads up to an unescaped stop character, removing backslash escapes.</summary>
    private static string ReadUntil(ReadOnlySpan<char> line, ref int i, char stop1, char stop2, char stop3)
    {
        var sb = new StringBuilder();
        while (i < line.Length)
        {
            var c = line[i];
            if (c == '\\' && i + 1 < line.Length)
            {
                sb.Append(line[i + 1]);
                i += 2;
                continue;
            }
            if (c == stop1 || c == stop2 || c == stop3)
            {
                break;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    private static bool SkipQuoted(ReadOnlySpan<char> line, ref int i)
    {
        i++; // opening quote
        while (i < line.Length)
        {
            if (line[i] == '\\' && i + 1 < line.Length)
            {
                i += 2;
                continue;
            }
            if (line[i++] == '"')
            {
                return true;
            }
        }
        return false;
    }

    private static void SkipSpaces(ReadOnlySpan<char> line, ref int i)
    {
        while (i < line.Length && line[i] == ' ')
        {
            i++;
        }
    }

    /// <summary>Prometheus-style names: anything but letters, digits, <c>_</c> and <c>:</c> becomes <c>_</c>.</summary>
    internal static string Sanitize(string name)
    {
        var chars = name.ToCharArray();
        for (var k = 0; k < chars.Length; k++)
        {
            if (!(char.IsAsciiLetterOrDigit(chars[k]) || chars[k] is '_' or ':'))
            {
                chars[k] = '_';
            }
        }
        return chars.Length > 0 && char.IsAsciiDigit(chars[0]) ? "_" + new string(chars) : new string(chars);
    }
}
