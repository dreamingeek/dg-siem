using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers;

/// <summary>
/// Unwraps events the agent's HTTP Event Collector buffered (input <c>hec</c>): one Splunk HEC object per
/// envelope, <c>{"time":…,"host":…,"source":…,"sourcetype":…,"index":…,"fields":{…},"event":…}</c>.
/// <list type="bullet">
/// <item>A string event (or Docker's <c>{"line": …}</c>) is parsed like any other log line, so a Traefik or
/// syslog line sent over HEC lands in the same dataset as it would over syslog.</item>
/// <item>An object event is flattened into dotted fields; common names (<c>level</c>, <c>msg</c>,
/// <c>user</c>, <c>client_ip</c>…) map onto the ECS columns.</item>
/// </list>
/// The HEC <c>time</c> and <c>host</c> fill in what the line itself doesn't say. <c>event.dataset</c> comes from
/// the agent input's dataset, then the sourcetype (<c>my:app</c> → <c>my.app</c>), then <c>hec</c>.
/// </summary>
public static class HecEvents
{
    public const string Input = "hec";
    public const string Dataset = "hec";

    private const int MaxFields = 256;
    private const int MaxDepth = 8;
    private const int MaxValueChars = 8192;

    /// <summary>The HEC metadata around one event.</summary>
    public sealed record Envelope(
        DateTimeOffset? Time, string? Host, string? Source, string? SourceType, string? Index,
        IReadOnlyList<KeyValuePair<string, string>> Fields, JsonElement Event);

    /// <summary>Reads the buffered HEC object. The returned document must be disposed by the caller.</summary>
    public static bool TryRead(string message, out Envelope? hec, out JsonDocument? document)
    {
        hec = null;
        document = null;
        if (message.Length == 0 || message[0] != '{')
        {
            return false;
        }
        try
        {
            document = JsonDocument.Parse(message);
        }
        catch (JsonException)
        {
            return false;
        }
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("event", out var evt))
        {
            document.Dispose();
            document = null;
            return false;
        }

        var fields = new List<KeyValuePair<string, string>>();
        if (root.TryGetProperty("fields", out var extra) && extra.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in extra.EnumerateObject())
            {
                var key = FieldName(p.Name);
                if (key is not null && Scalar(p.Value) is { } value)
                {
                    fields.Add(new(key, value));
                }
            }
        }
        hec = new Envelope(Time(root), Text(root, "host"), Text(root, "source"), Text(root, "sourcetype"), Text(root, "index"), fields, evt);
        return true;
    }

    /// <summary>A sourcetype as a dataset name: <c>_json</c> and blanks give null, <c>my:App</c> gives <c>my.app</c>.</summary>
    public static string? DatasetFor(string? sourceType)
    {
        if (string.IsNullOrWhiteSpace(sourceType))
        {
            return null;
        }
        var sb = new StringBuilder(sourceType.Length);
        foreach (var c in sourceType.Trim().ToLowerInvariant())
        {
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' ? c : '.');
        }
        var name = string.Join('.', sb.ToString().Split('.', StringSplitOptions.RemoveEmptyEntries)).Trim('_', '-');
        // Splunk's built-in "_json"/"httpevent" say nothing about the source.
        return name.Length == 0 || name.Length > 64 || name is "json" or "_json" or "httpevent" or "generic_single_line" ? null : name;
    }

    /// <summary>
    /// The line inside a string event, or Docker's splunk logging driver (<c>splunk-format=inline</c>):
    /// <c>{"line": "...", "source": "stdout", "tag": "..."}</c>.
    /// </summary>
    public static string? Line(JsonElement evt) => evt.ValueKind switch
    {
        JsonValueKind.String => evt.GetString(),
        JsonValueKind.Object when evt.TryGetProperty("line", out var line) && line.ValueKind == JsonValueKind.String => line.GetString(),
        _ => null,
    };

    /// <summary>An object (or number/bool/array) event as a <see cref="LogEvent"/>.</summary>
    public static LogEvent FromObject(JsonElement evt, string tenantId, DateTimeOffset time, string? observerIp, string dataset)
    {
        var raw = evt.GetRawText();
        var e = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = time,
            ObserverIp = observerIp ?? string.Empty,
            EventDataset = dataset,
            EventModule = Dataset,
            Raw = Compact(evt),
        };
        if (evt.ValueKind != JsonValueKind.Object)
        {
            e.Message = Scalar(evt) ?? raw;
            return e;
        }

        var flat = new List<KeyValuePair<string, string>>();
        Flatten(evt, null, 0, flat);
        foreach (var (key, value) in flat)
        {
            if (!Promote(e, key, value) && e.Fields.Count < MaxFields)
            {
                e.Fields.TryAdd(key, value);
            }
        }
        if (e.Message.Length == 0)
        {
            e.Message = e.Raw;
        }
        return e;
    }

    /// <summary>Docker's extra keys next to <c>line</c> (<c>source</c>, <c>tag</c>, <c>attrs</c>) as <c>docker.*</c> fields.</summary>
    public static void AddDockerFields(JsonElement evt, LogEvent e)
    {
        if (evt.ValueKind != JsonValueKind.Object)
        {
            return;
        }
        var flat = new List<KeyValuePair<string, string>>();
        foreach (var p in evt.EnumerateObject())
        {
            if (p.Name != "line" && FieldName(p.Name) is { } key)
            {
                Flatten(p.Value, "docker." + key, 1, flat);
            }
        }
        foreach (var (key, value) in flat)
        {
            e.Fields.TryAdd(key == "docker.source" ? "docker.stream" : key, value);
        }
    }

    /// <summary>Applies the HEC metadata to an event parsed from the line or object.</summary>
    public static void ApplyMetadata(Envelope hec, LogEvent e)
    {
        ArgumentNullException.ThrowIfNull(hec);
        ArgumentNullException.ThrowIfNull(e);
        if (e.HostName.Length == 0 && hec.Host is { Length: > 0 } host)
        {
            e.HostName = host;
        }
        if (hec.Source is { Length: > 0 } source)
        {
            e.Fields.TryAdd("hec.source", source);
        }
        if (hec.SourceType is { Length: > 0 } sourceType)
        {
            e.Fields.TryAdd("hec.sourcetype", sourceType);
        }
        if (hec.Index is { Length: > 0 } index)
        {
            e.Fields.TryAdd("hec.index", index);
        }
        foreach (var (key, value) in hec.Fields)
        {
            if (!Promote(e, key, value, onlyIfEmpty: true))
            {
                e.Fields.TryAdd(key, value);
            }
        }
    }

    /// <summary>Sets an ECS column from a well-known key. Returns false when the key isn't one.</summary>
    private static bool Promote(LogEvent e, string key, string value, bool onlyIfEmpty = false)
    {
        switch (key.ToLowerInvariant())
        {
            case EcsField.Message or "msg" or "log" or "text" or "event.original":
                if (e.Message.Length == 0 || (!onlyIfEmpty && key == EcsField.Message))
                {
                    e.Message = value;
                    return true;
                }
                return key == EcsField.Message;
            case EcsField.LogLevel or "level" or "severity" or "loglevel" or "lvl" or "log_level":
                Set(e.LogLevel, v => e.LogLevel = v, value.ToLowerInvariant(), onlyIfEmpty);
                return true;
            case EcsField.HostName or "hostname" or "host":
                Set(e.HostName, v => e.HostName = v, value, onlyIfEmpty);
                return true;
            case EcsField.UserName or "user" or "username" or "user_name":
                Set(e.UserName, v => e.UserName = v, value, onlyIfEmpty);
                return true;
            case EcsField.EventAction or "action":
                Set(e.EventAction, v => e.EventAction = v, value, onlyIfEmpty);
                return true;
            case EcsField.EventOutcome or "outcome":
                Set(e.EventOutcome, v => e.EventOutcome = v, value.ToLowerInvariant(), onlyIfEmpty);
                return true;
            case EcsField.EventModule:
                Set(e.EventModule, v => e.EventModule = v, value, onlyIfEmpty: false);
                return true;
            case EcsField.EventDataset:
                if (DatasetFor(value) is { } dataset)
                {
                    e.EventDataset = dataset;
                }
                return true;
            case EcsField.SourceIp or "src_ip" or "client_ip" or "clientip" or "remote_addr" or "remote_ip" or "ip" or "src":
                return SetIp(value, ip => e.SourceIp = ip, e.SourceIp, onlyIfEmpty);
            case EcsField.DestinationIp or "dest_ip" or "dst_ip" or "dst":
                return SetIp(value, ip => e.DestinationIp = ip, e.DestinationIp, onlyIfEmpty);
            case EcsField.SourcePort or "src_port":
                return SetPort(value, p => e.SourcePort = p, e.SourcePort, onlyIfEmpty);
            case EcsField.DestinationPort or "dest_port" or "dst_port":
                return SetPort(value, p => e.DestinationPort = p, e.DestinationPort, onlyIfEmpty);
            case EcsField.NetworkTransport or "proto" or "protocol":
                Set(e.NetworkTransport, v => e.NetworkTransport = v, value.ToLowerInvariant(), onlyIfEmpty);
                return true;
            case EcsField.NetworkProtocol:
                Set(e.NetworkProtocol, v => e.NetworkProtocol = v, value.ToLowerInvariant(), onlyIfEmpty);
                return true;
            default:
                return false;
        }
    }

    private static void Set(string current, Action<string> set, string value, bool onlyIfEmpty)
    {
        if (!onlyIfEmpty || current.Length == 0)
        {
            set(value);
        }
    }

    /// <summary>Only a real address goes in the IP column; anything else stays a plain field.</summary>
    private static bool SetIp(string value, Action<string> set, string current, bool onlyIfEmpty)
    {
        if (!IPAddress.TryParse(value, out var ip))
        {
            return false;
        }
        if (!onlyIfEmpty || current.Length == 0)
        {
            set((ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString());
        }
        return true;
    }

    private static bool SetPort(string value, Action<ushort> set, ushort current, bool onlyIfEmpty)
    {
        if (!ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            return false;
        }
        if (!onlyIfEmpty || current == 0)
        {
            set(port);
        }
        return true;
    }

    private static void Flatten(JsonElement value, string? prefix, int depth, List<KeyValuePair<string, string>> into)
    {
        if (into.Count >= MaxFields)
        {
            return;
        }
        if (value.ValueKind == JsonValueKind.Object && depth < MaxDepth)
        {
            foreach (var p in value.EnumerateObject())
            {
                if (FieldName(p.Name) is { } name)
                {
                    Flatten(p.Value, prefix is null ? name : prefix + "." + name, depth + 1, into);
                }
            }
            return;
        }
        if (prefix is not null && Scalar(value) is { } text)
        {
            into.Add(new(prefix, text));
        }
    }

    /// <summary>A value as field text: strings as-is, scalar arrays comma-joined, anything else as compact JSON.</summary>
    private static string? Scalar(JsonElement value)
    {
        var text = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            JsonValueKind.Array when value.EnumerateArray().All(v => v.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False) =>
                string.Join(", ", value.EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText())),
            _ => Compact(value),
        };
        return text is { Length: > MaxValueChars } ? text[..MaxValueChars] : text;
    }

    /// <summary>A JSON key as a field name the query language can address: letters, digits, <c>_</c>, <c>-</c>, dots.</summary>
    private static string? FieldName(string key)
    {
        var sb = new StringBuilder(key.Length);
        foreach (var c in key.Trim())
        {
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' ? c : '_');
        }
        var name = string.Join('.', sb.ToString().Split('.', StringSplitOptions.RemoveEmptyEntries));
        return name.Length is 0 or > 128 || name is "raw" or "@timestamp" ? null : name;
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;

    /// <summary>HEC <c>time</c>: epoch seconds, number or string, with optional fraction.</summary>
    private static DateTimeOffset? Time(JsonElement root)
    {
        if (!root.TryGetProperty("time", out var t))
        {
            return null;
        }
        decimal seconds;
        if (t.ValueKind == JsonValueKind.Number && t.TryGetDecimal(out var n))
        {
            seconds = n;
        }
        else if (t.ValueKind == JsonValueKind.String && decimal.TryParse(t.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var s))
        {
            seconds = s;
        }
        else
        {
            return null;
        }
        // Milliseconds sent by mistake (13 digits) are common; anything outside 2000..2100 is ignored.
        if (seconds > 100_000_000_000m)
        {
            seconds /= 1000m;
        }
        if (seconds is < 946_684_800m or > 4_102_444_800m)
        {
            return null;
        }
        return DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000m));
    }

    private static string Compact(JsonElement element)
    {
        using var json = new MemoryStream();
        using (var writer = new Utf8JsonWriter(json))
        {
            element.WriteTo(writer);
        }
        return Encoding.UTF8.GetString(json.ToArray());
    }
}
