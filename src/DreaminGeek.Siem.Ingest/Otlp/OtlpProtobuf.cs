using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DreaminGeek.Siem.Ingest.Otlp;

/// <summary>
/// Reads OTLP protobuf (ExportLogsServiceRequest, ExportMetricsServiceRequest) without generated code: only the
/// fields DG SIEM uses, by their numbers in opentelemetry-proto v1. Unknown fields are skipped, as protobuf requires.
/// </summary>
public static class OtlpProtobuf
{
    private const int MaxDepth = 32;

    public static List<OtlpLogRecord> ReadLogs(ReadOnlySpan<byte> request)
    {
        var records = new List<OtlpLogRecord>();
        var r = new Reader(request);
        while (r.Next(out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                ReadResourceLogs(r.Bytes(), records);
            }
            else
            {
                r.Skip(wire);
            }
        }
        return records;
    }

    public static List<OtlpPoint> ReadMetrics(ReadOnlySpan<byte> request)
    {
        var points = new List<OtlpPoint>();
        var r = new Reader(request);
        while (r.Next(out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                ReadResourceMetrics(r.Bytes(), points);
            }
            else
            {
                r.Skip(wire);
            }
        }
        return points;
    }

    private static void ReadResourceLogs(ReadOnlySpan<byte> data, List<OtlpLogRecord> records)
    {
        IReadOnlyList<OtlpKeyValue> resource = [];
        var scopes = new List<(int Start, int Length)>();
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    resource = ReadResource(r.Bytes());
                    break;
                case (2, 2):
                    var length = r.Bytes().Length;
                    scopes.Add((r.Position - length, length));
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        // The resource can come after its scopes; read them once it's known.
        foreach (var (start, length) in scopes)
        {
            ReadScopeLogs(data.Slice(start, length), resource, records);
        }
    }

    private static void ReadScopeLogs(ReadOnlySpan<byte> data, IReadOnlyList<OtlpKeyValue> resource, List<OtlpLogRecord> records)
    {
        string? scope = null;
        var first = records.Count;
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    scope = ReadScopeName(r.Bytes());
                    break;
                case (2, 2):
                    var record = ReadLogRecord(r.Bytes());
                    record.Resource = resource;
                    records.Add(record);
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        for (var i = first; i < records.Count; i++)
        {
            records[i].Scope = scope;
        }
    }

    private static OtlpLogRecord ReadLogRecord(ReadOnlySpan<byte> data)
    {
        var record = new OtlpLogRecord();
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 1):
                    record.TimeUnixNano = r.Fixed64();
                    break;
                case (11, 1):
                    record.ObservedTimeUnixNano = r.Fixed64();
                    break;
                case (2, 0):
                    record.SeverityNumber = (int)r.Varint();
                    break;
                case (3, 2):
                    record.SeverityText = r.String();
                    break;
                case (5, 2):
                    record.Body = AnyValueText(r.Bytes(), 0);
                    break;
                case (6, 2):
                    if (ReadKeyValue(r.Bytes(), 0) is { } attribute)
                    {
                        record.Attributes.Add(attribute);
                    }
                    break;
                case (9, 2):
                    record.TraceId = Hex(r.Bytes());
                    break;
                case (10, 2):
                    record.SpanId = Hex(r.Bytes());
                    break;
                case (12, 2):
                    record.EventName = r.String();
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        return record;
    }

    private static void ReadResourceMetrics(ReadOnlySpan<byte> data, List<OtlpPoint> points)
    {
        IReadOnlyList<OtlpKeyValue> resource = [];
        var scopes = new List<(int Start, int Length)>();
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    resource = ReadResource(r.Bytes());
                    break;
                case (2, 2):
                    var length = r.Bytes().Length;
                    scopes.Add((r.Position - length, length));
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        foreach (var (start, length) in scopes)
        {
            var s = new Reader(data.Slice(start, length));
            while (s.Next(out var field, out var wire))
            {
                if (field == 2 && wire == 2)
                {
                    ReadMetric(s.Bytes(), resource, points);
                }
                else
                {
                    s.Skip(wire);
                }
            }
        }
    }

    private static void ReadMetric(ReadOnlySpan<byte> data, IReadOnlyList<OtlpKeyValue> resource, List<OtlpPoint> points)
    {
        string name = string.Empty;
        string? unit = null;
        var first = points.Count;
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    name = r.String();
                    break;
                case (3, 2):
                    unit = r.String();
                    break;
                case (5, 2):
                    ReadData(r.Bytes(), OtlpMetricKind.Gauge, points);
                    break;
                case (7, 2):
                    ReadData(r.Bytes(), OtlpMetricKind.Sum, points);
                    break;
                case (9, 2):
                    ReadData(r.Bytes(), OtlpMetricKind.Histogram, points);
                    break;
                case (10, 2):
                    ReadData(r.Bytes(), OtlpMetricKind.ExponentialHistogram, points);
                    break;
                case (11, 2):
                    ReadData(r.Bytes(), OtlpMetricKind.Summary, points);
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        for (var i = first; i < points.Count; i++)
        {
            (points[i].Name, points[i].Unit, points[i].Resource) = (name, unit, resource);
        }
    }

    /// <summary>Gauge, Sum, Histogram, ExponentialHistogram or Summary: data points (1), temporality (2), monotonic (3).</summary>
    private static void ReadData(ReadOnlySpan<byte> data, OtlpMetricKind kind, List<OtlpPoint> points)
    {
        var first = points.Count;
        var cumulative = true;
        var monotonic = false;
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    points.Add(ReadPoint(r.Bytes(), kind));
                    break;
                case (2, 0) when kind != OtlpMetricKind.Gauge && kind != OtlpMetricKind.Summary:
                    cumulative = r.Varint() != 1; // 1 = DELTA, 2 = CUMULATIVE
                    break;
                case (3, 0) when kind == OtlpMetricKind.Sum:
                    monotonic = r.Varint() != 0;
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        for (var i = first; i < points.Count; i++)
        {
            (points[i].Cumulative, points[i].Monotonic) = (cumulative, monotonic);
        }
    }

    private static OtlpPoint ReadPoint(ReadOnlySpan<byte> data, OtlpMetricKind kind)
    {
        var p = new OtlpPoint { Kind = kind };
        // The attributes field number differs by point type.
        var attributesField = kind switch
        {
            OtlpMetricKind.Histogram => 9,
            OtlpMetricKind.ExponentialHistogram => 1,
            _ => 7,
        };
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            if (field == attributesField && wire == 2)
            {
                if (ReadKeyValue(r.Bytes(), 0) is { } attribute)
                {
                    p.Attributes.Add(attribute);
                }
                continue;
            }
            switch (kind, field, wire)
            {
                case (_, 3, 1):
                    p.TimeUnixNano = r.Fixed64();
                    break;
                case (OtlpMetricKind.Gauge or OtlpMetricKind.Sum, 4, 1):
                    p.Value = BitConverter.UInt64BitsToDouble(r.Fixed64());
                    break;
                case (OtlpMetricKind.Gauge or OtlpMetricKind.Sum, 6, 1):
                    p.Value = unchecked((long)r.Fixed64());
                    break;
                case (not (OtlpMetricKind.Gauge or OtlpMetricKind.Sum), 4, 1):
                    p.Count = r.Fixed64();
                    break;
                case (not (OtlpMetricKind.Gauge or OtlpMetricKind.Sum), 5, 1):
                    p.Sum = BitConverter.UInt64BitsToDouble(r.Fixed64());
                    break;
                case (OtlpMetricKind.Histogram, 6, 2):
                    var counts = r.Bytes();
                    for (var i = 0; i + 8 <= counts.Length; i += 8)
                    {
                        p.BucketCounts.Add(BinaryPrimitives.ReadUInt64LittleEndian(counts[i..]));
                    }
                    break;
                case (OtlpMetricKind.Histogram, 6, 1):
                    p.BucketCounts.Add(r.Fixed64());
                    break;
                case (OtlpMetricKind.Histogram, 7, 2):
                    var bounds = r.Bytes();
                    for (var i = 0; i + 8 <= bounds.Length; i += 8)
                    {
                        p.ExplicitBounds.Add(BitConverter.UInt64BitsToDouble(BinaryPrimitives.ReadUInt64LittleEndian(bounds[i..])));
                    }
                    break;
                case (OtlpMetricKind.Histogram, 7, 1):
                    p.ExplicitBounds.Add(BitConverter.UInt64BitsToDouble(r.Fixed64()));
                    break;
                case (OtlpMetricKind.Summary, 6, 2):
                    p.Quantiles.Add(ReadQuantile(r.Bytes()));
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        return p;
    }

    private static (double, double) ReadQuantile(ReadOnlySpan<byte> data)
    {
        double quantile = 0, value = 0;
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 1):
                    quantile = BitConverter.UInt64BitsToDouble(r.Fixed64());
                    break;
                case (2, 1):
                    value = BitConverter.UInt64BitsToDouble(r.Fixed64());
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        return (quantile, value);
    }

    private static List<OtlpKeyValue> ReadResource(ReadOnlySpan<byte> data)
    {
        var attributes = new List<OtlpKeyValue>();
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            if (field == 1 && wire == 2 && ReadKeyValue(r.Bytes(), 0) is { } attribute)
            {
                attributes.Add(attribute);
            }
            else if (!(field == 1 && wire == 2))
            {
                r.Skip(wire);
            }
        }
        return attributes;
    }

    private static string? ReadScopeName(ReadOnlySpan<byte> data)
    {
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                return r.String();
            }
            r.Skip(wire);
        }
        return null;
    }

    private static OtlpKeyValue? ReadKeyValue(ReadOnlySpan<byte> data, int depth)
    {
        string? key = null;
        string? value = null;
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    key = r.String();
                    break;
                case (2, 2):
                    value = AnyValueText(r.Bytes(), depth + 1);
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        return key is null ? null : new OtlpKeyValue(key, value ?? string.Empty);
    }

    /// <summary>An AnyValue as text: strings as they are, numbers and booleans in invariant form, arrays and maps as JSON.</summary>
    private static string? AnyValueText(ReadOnlySpan<byte> data, int depth)
    {
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    return r.String();
                case (2, 0):
                    return r.Varint() != 0 ? "true" : "false";
                case (3, 0):
                    return unchecked((long)r.Varint()).ToString(CultureInfo.InvariantCulture);
                case (4, 1):
                    return Number(BitConverter.UInt64BitsToDouble(r.Fixed64()));
                case (5 or 6, 2):
                    if (depth >= MaxDepth)
                    {
                        throw new OtlpFormatException("Values are nested too deeply.");
                    }
                    var nested = r.Bytes();
                    using (var stream = new MemoryStream())
                    {
                        using (var json = new Utf8JsonWriter(stream))
                        {
                            WriteJson(json, nested, field == 6, depth + 1);
                        }
                        return Encoding.UTF8.GetString(stream.ToArray());
                    }
                case (7, 2):
                    return Convert.ToBase64String(r.Bytes());
                default:
                    r.Skip(wire);
                    break;
            }
        }
        return null;
    }

    /// <summary>An ArrayValue (values = 1) or KeyValueList (values = 1) as JSON.</summary>
    private static void WriteJson(Utf8JsonWriter json, ReadOnlySpan<byte> data, bool map, int depth)
    {
        if (map)
        {
            json.WriteStartObject();
        }
        else
        {
            json.WriteStartArray();
        }
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            if (field != 1 || wire != 2)
            {
                r.Skip(wire);
                continue;
            }
            var item = r.Bytes();
            if (map)
            {
                var kv = new Reader(item);
                string key = string.Empty;
                ReadOnlySpan<byte> value = default;
                while (kv.Next(out var f, out var w))
                {
                    if (f == 1 && w == 2)
                    {
                        key = kv.String();
                    }
                    else if (f == 2 && w == 2)
                    {
                        value = kv.Bytes();
                    }
                    else
                    {
                        kv.Skip(w);
                    }
                }
                json.WritePropertyName(key);
                WriteAnyValue(json, value, depth);
            }
            else
            {
                WriteAnyValue(json, item, depth);
            }
        }
        if (map)
        {
            json.WriteEndObject();
        }
        else
        {
            json.WriteEndArray();
        }
    }

    private static void WriteAnyValue(Utf8JsonWriter json, ReadOnlySpan<byte> data, int depth)
    {
        if (depth >= MaxDepth)
        {
            throw new OtlpFormatException("Values are nested too deeply.");
        }
        var r = new Reader(data);
        while (r.Next(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2):
                    json.WriteStringValue(r.String());
                    return;
                case (2, 0):
                    json.WriteBooleanValue(r.Varint() != 0);
                    return;
                case (3, 0):
                    json.WriteNumberValue(unchecked((long)r.Varint()));
                    return;
                case (4, 1):
                    var d = BitConverter.UInt64BitsToDouble(r.Fixed64());
                    if (double.IsFinite(d))
                    {
                        json.WriteNumberValue(d);
                    }
                    else
                    {
                        json.WriteStringValue(Number(d));
                    }
                    return;
                case (5 or 6, 2):
                    WriteJson(json, r.Bytes(), field == 6, depth + 1);
                    return;
                case (7, 2):
                    json.WriteStringValue(Convert.ToBase64String(r.Bytes()));
                    return;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        json.WriteNullValue();
    }

    internal static string Number(double value) => value.ToString("R", CultureInfo.InvariantCulture);

    private static string? Hex(ReadOnlySpan<byte> bytes) =>
        bytes.IsEmpty || !bytes.ContainsAnyExcept((byte)0) ? null : Convert.ToHexStringLower(bytes);

    /// <summary>Protobuf wire format: varints, fixed 64/32-bit values and length-delimited bytes.</summary>
    private ref struct Reader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _position;

        public readonly int Position => _position;

        public bool Next(out int field, out int wire)
        {
            if (_position >= _data.Length)
            {
                field = wire = 0;
                return false;
            }
            var tag = Varint();
            field = (int)(tag >> 3);
            wire = (int)(tag & 7);
            if (field == 0)
            {
                throw new OtlpFormatException("Not a protobuf message.");
            }
            return true;
        }

        public ulong Varint()
        {
            ulong value = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                if (_position >= _data.Length)
                {
                    throw new OtlpFormatException("The message ends early.");
                }
                var b = _data[_position++];
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    return value;
                }
            }
            throw new OtlpFormatException("A number is too long.");
        }

        public ulong Fixed64()
        {
            Need(8);
            var value = BinaryPrimitives.ReadUInt64LittleEndian(_data[_position..]);
            _position += 8;
            return value;
        }

        public ReadOnlySpan<byte> Bytes()
        {
            var length = Varint();
            if (length > int.MaxValue)
            {
                throw new OtlpFormatException("A field is too long.");
            }
            Need((int)length);
            var bytes = _data.Slice(_position, (int)length);
            _position += (int)length;
            return bytes;
        }

        public string String() => Encoding.UTF8.GetString(Bytes());

        public void Skip(int wire)
        {
            switch (wire)
            {
                case 0:
                    Varint();
                    break;
                case 1:
                    Need(8);
                    _position += 8;
                    break;
                case 2:
                    Bytes();
                    break;
                case 5:
                    Need(4);
                    _position += 4;
                    break;
                default:
                    throw new OtlpFormatException($"Unsupported wire type {wire}.");
            }
        }

        private readonly void Need(int count)
        {
            if (count < 0 || _position + count > _data.Length)
            {
                throw new OtlpFormatException("The message ends early.");
            }
        }
    }
}
