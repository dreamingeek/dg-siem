using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DreaminGeek.Siem.Ingest.Otlp;

/// <summary>
/// Reads OTLP/JSON (the protobuf messages in proto3 JSON form: lowerCamelCase names, 64-bit numbers as strings or
/// numbers, enums as numbers or names, trace and span ids as hex).
/// </summary>
public static class OtlpJson
{
    private const int MaxDepth = 32;

    public static List<OtlpLogRecord> ReadLogs(ReadOnlySpan<byte> request)
    {
        var records = new List<OtlpLogRecord>();
        using var document = Parse(request);
        foreach (var rl in Array(document.RootElement, "resourceLogs"))
        {
            var resource = Attributes(Object(rl, "resource"));
            foreach (var sl in Array(rl, "scopeLogs"))
            {
                var scope = Object(sl, "scope") is { } s ? Text(s, "name") : null;
                foreach (var lr in Array(sl, "logRecords"))
                {
                    var record = new OtlpLogRecord
                    {
                        Resource = resource,
                        Scope = scope,
                        TimeUnixNano = UInt64(lr, "timeUnixNano"),
                        ObservedTimeUnixNano = UInt64(lr, "observedTimeUnixNano"),
                        SeverityNumber = Severity(lr),
                        SeverityText = Text(lr, "severityText"),
                        Body = lr.TryGetProperty("body", out var body) ? AnyValueText(body, 0) : null,
                        TraceId = NonZero(Text(lr, "traceId")),
                        SpanId = NonZero(Text(lr, "spanId")),
                        EventName = Text(lr, "eventName"),
                    };
                    record.Attributes.AddRange(Attributes(lr));
                    records.Add(record);
                }
            }
        }
        return records;
    }

    public static List<OtlpPoint> ReadMetrics(ReadOnlySpan<byte> request)
    {
        var points = new List<OtlpPoint>();
        using var document = Parse(request);
        foreach (var rm in Array(document.RootElement, "resourceMetrics"))
        {
            var resource = Attributes(Object(rm, "resource"));
            foreach (var sm in Array(rm, "scopeMetrics"))
            {
                foreach (var m in Array(sm, "metrics"))
                {
                    var name = Text(m, "name") ?? string.Empty;
                    var unit = Text(m, "unit");
                    foreach (var (property, kind) in new[]
                    {
                        ("gauge", OtlpMetricKind.Gauge), ("sum", OtlpMetricKind.Sum), ("histogram", OtlpMetricKind.Histogram),
                        ("exponentialHistogram", OtlpMetricKind.ExponentialHistogram), ("summary", OtlpMetricKind.Summary),
                    })
                    {
                        if (Object(m, property) is not { } data)
                        {
                            continue;
                        }
                        var cumulative = !IsDelta(data);
                        var monotonic = data.TryGetProperty("isMonotonic", out var mono) && mono.ValueKind == JsonValueKind.True;
                        foreach (var dp in Array(data, "dataPoints"))
                        {
                            var p = new OtlpPoint
                            {
                                Resource = resource, Name = name, Unit = unit, Kind = kind, Cumulative = cumulative, Monotonic = monotonic,
                                TimeUnixNano = UInt64(dp, "timeUnixNano"),
                            };
                            p.Attributes.AddRange(Attributes(dp));
                            if (kind is OtlpMetricKind.Gauge or OtlpMetricKind.Sum)
                            {
                                p.Value = dp.TryGetProperty("asDouble", out var d) ? Double(d) : (double)Int64(dp, "asInt");
                            }
                            else
                            {
                                p.Count = UInt64(dp, "count");
                                p.Sum = dp.TryGetProperty("sum", out var sum) ? Double(sum) : null;
                                foreach (var c in Array(dp, "bucketCounts"))
                                {
                                    p.BucketCounts.Add(UInt64(c));
                                }
                                foreach (var b in Array(dp, "explicitBounds"))
                                {
                                    p.ExplicitBounds.Add(Double(b));
                                }
                                foreach (var q in Array(dp, "quantileValues"))
                                {
                                    p.Quantiles.Add((q.TryGetProperty("quantile", out var qq) ? Double(qq) : 0, q.TryGetProperty("value", out var qv) ? Double(qv) : 0));
                                }
                            }
                            points.Add(p);
                        }
                    }
                }
            }
        }
        return points;
    }

    private static JsonDocument Parse(ReadOnlySpan<byte> request)
    {
        try
        {
            return JsonDocument.Parse(request.ToArray(), new JsonDocumentOptions { MaxDepth = 64 });
        }
        catch (JsonException ex)
        {
            throw new OtlpFormatException("Not valid JSON: " + ex.Message);
        }
    }

    private static bool IsDelta(JsonElement data) =>
        data.TryGetProperty("aggregationTemporality", out var t) &&
        (t.ValueKind == JsonValueKind.Number ? t.GetInt32() == 1 : t.GetString() == "AGGREGATION_TEMPORALITY_DELTA");

    private static int Severity(JsonElement record)
    {
        if (!record.TryGetProperty("severityNumber", out var s))
        {
            return 0;
        }
        if (s.ValueKind == JsonValueKind.Number)
        {
            return s.GetInt32();
        }
        // SEVERITY_NUMBER_WARN2 and so on.
        var name = s.GetString() ?? string.Empty;
        var levels = new[] { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
        for (var i = 0; i < levels.Length; i++)
        {
            var prefix = "SEVERITY_NUMBER_" + levels[i];
            if (name.StartsWith(prefix, StringComparison.Ordinal))
            {
                var step = name.Length > prefix.Length && int.TryParse(name.AsSpan(prefix.Length), CultureInfo.InvariantCulture, out var n) ? n : 1;
                return i * 4 + Math.Clamp(step, 1, 4);
            }
        }
        return 0;
    }

    private static List<JsonElement> Array(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var a) && a.ValueKind == JsonValueKind.Array
            ? [.. a.EnumerateArray()]
            : [];

    private static List<JsonElement> Array(JsonElement? element, string property) =>
        element is { } e ? Array(e, property) : [];

    private static JsonElement? Object(JsonElement element, string property) =>
        element.TryGetProperty(property, out var o) && o.ValueKind == JsonValueKind.Object ? o : null;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;

    private static ulong UInt64(JsonElement element, string property) =>
        element.TryGetProperty(property, out var v) ? UInt64(v) : 0;

    private static ulong UInt64(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.Number when v.TryGetUInt64(out var n) => n,
        JsonValueKind.String when ulong.TryParse(v.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var n) => n,
        _ => 0,
    };

    private static long Int64(JsonElement element, string property) =>
        !element.TryGetProperty(property, out var v) ? 0 : v.ValueKind switch
        {
            JsonValueKind.Number when v.TryGetInt64(out var n) => n,
            JsonValueKind.String when long.TryParse(v.GetString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n) => n,
            _ => 0,
        };

    private static double Double(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.Number => v.GetDouble(),
        // proto3 JSON writes non-finite doubles as strings.
        JsonValueKind.String => v.GetString() switch
        {
            "NaN" => double.NaN,
            "Infinity" => double.PositiveInfinity,
            "-Infinity" => double.NegativeInfinity,
            var s => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0,
        },
        _ => 0,
    };

    private static string? NonZero(string? hex) =>
        string.IsNullOrEmpty(hex) || hex.All(c => c == '0') ? null : hex.ToLowerInvariant();

    private static List<OtlpKeyValue> Attributes(JsonElement? element)
    {
        var list = new List<OtlpKeyValue>();
        foreach (var kv in Array(element, "attributes"))
        {
            if (Text(kv, "key") is { } key)
            {
                list.Add(new OtlpKeyValue(key, kv.TryGetProperty("value", out var v) ? AnyValueText(v, 0) ?? string.Empty : string.Empty));
            }
        }
        return list;
    }

    private static string? AnyValueText(JsonElement value, int depth)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        if (value.TryGetProperty("stringValue", out var s))
        {
            return s.GetString();
        }
        if (value.TryGetProperty("boolValue", out var b))
        {
            return b.ValueKind == JsonValueKind.True ? "true" : "false";
        }
        if (value.TryGetProperty("intValue", out _))
        {
            return Int64(value, "intValue").ToString(CultureInfo.InvariantCulture);
        }
        if (value.TryGetProperty("doubleValue", out var d))
        {
            return OtlpProtobuf.Number(Double(d));
        }
        if (value.TryGetProperty("bytesValue", out var bytes))
        {
            return bytes.GetString();
        }
        if (value.TryGetProperty("arrayValue", out _) || value.TryGetProperty("kvlistValue", out _))
        {
            using var stream = new MemoryStream();
            using (var json = new Utf8JsonWriter(stream))
            {
                WriteAnyValue(json, value, depth);
            }
            return Encoding.UTF8.GetString(stream.ToArray());
        }
        return null;
    }

    private static void WriteAnyValue(Utf8JsonWriter json, JsonElement value, int depth)
    {
        if (depth >= MaxDepth)
        {
            throw new OtlpFormatException("Values are nested too deeply.");
        }
        if (value.ValueKind != JsonValueKind.Object)
        {
            json.WriteNullValue();
            return;
        }
        if (value.TryGetProperty("arrayValue", out var array))
        {
            json.WriteStartArray();
            foreach (var item in Array(array, "values"))
            {
                WriteAnyValue(json, item, depth + 1);
            }
            json.WriteEndArray();
        }
        else if (value.TryGetProperty("kvlistValue", out var map))
        {
            json.WriteStartObject();
            foreach (var kv in Array(map, "values"))
            {
                json.WritePropertyName(Text(kv, "key") ?? string.Empty);
                if (kv.TryGetProperty("value", out var v))
                {
                    WriteAnyValue(json, v, depth + 1);
                }
                else
                {
                    json.WriteNullValue();
                }
            }
            json.WriteEndObject();
        }
        else if (value.TryGetProperty("stringValue", out var s))
        {
            json.WriteStringValue(s.GetString());
        }
        else if (value.TryGetProperty("boolValue", out var b))
        {
            json.WriteBooleanValue(b.ValueKind == JsonValueKind.True);
        }
        else if (value.TryGetProperty("intValue", out _))
        {
            json.WriteNumberValue(Int64(value, "intValue"));
        }
        else if (value.TryGetProperty("doubleValue", out var d) && double.IsFinite(Double(d)))
        {
            json.WriteNumberValue(Double(d));
        }
        else if (value.TryGetProperty("bytesValue", out var bytes))
        {
            json.WriteStringValue(bytes.GetString());
        }
        else
        {
            json.WriteNullValue();
        }
    }
}
