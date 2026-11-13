using System.Globalization;
using System.Text.Json;

namespace DreaminGeek.Siem.Ingest.ThreatIntel;

public enum ThreatFeedFormat
{
    /// <summary>One address or CIDR range per line; <c>#</c> and <c>;</c> start comments, anything after the first word is ignored.</summary>
    PlainText,

    /// <summary>Spamhaus DROP: one JSON object per line (<c>cidr</c>, <c>sblid</c>), the last line metadata.</summary>
    SpamhausDrop,

    /// <summary>abuse.ch Feodo Tracker: a JSON array of <c>ip_address</c>, <c>malware</c>, <c>status</c>.</summary>
    FeodoJson,

    /// <summary>abuse.ch ThreatFox export: <c>{"id": [{"ioc_value": "ip:port", "malware_printable": ...}]}</c>.</summary>
    ThreatFoxJson,
}

/// <summary>
/// A feed DG SIEM can download. Each install downloads from the publisher directly, under the publisher's terms:
/// DG SIEM doesn't redistribute any list.
/// </summary>
/// <param name="Interval">How often to download; publishers set limits (Spamhaus: once a day).</param>
/// <param name="KeepDays">For feeds that only list recent sightings: keep each address this long after it was last seen.</param>
/// <param name="EntryDescription">Why an address on a plain list is listed (plain lists don't say).</param>
public sealed record ThreatFeedDefinition(
    string Id, string Name, string Url, ThreatFeedFormat Format, TimeSpan Interval, bool OnByDefault,
    string About, string TermsUrl, string? Caution = null, int KeepDays = 0, string EntryDescription = "Listed");

public static class ThreatFeeds
{
    public const string OwnListId = "own";
    public const string OwnListName = "Your list";

    public static readonly IReadOnlyList<ThreatFeedDefinition> BuiltIn =
    [
        new("spamhaus-drop-v4", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v4.json", ThreatFeedFormat.SpamhausDrop,
            TimeSpan.FromDays(1), OnByDefault: true,
            "IPv4 ranges run by spammers and criminal networks (Do Not Route Or Peer). Very few false positives.",
            "https://www.spamhaus.org/drop/terms/"),
        new("spamhaus-drop-v6", "Spamhaus DROPv6", "https://www.spamhaus.org/drop/drop_v6.json", ThreatFeedFormat.SpamhausDrop,
            TimeSpan.FromDays(1), OnByDefault: true,
            "The same for IPv6.",
            "https://www.spamhaus.org/drop/terms/"),
        new("feodo", "Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", ThreatFeedFormat.FeodoJson,
            TimeSpan.FromHours(1), OnByDefault: true,
            "Botnet command-and-control servers (Dridex, Emotet, QakBot and similar). Free for any use (CC0).",
            "https://abuse.ch/terms-of-use/"),
        new("threatfox", "ThreatFox", "https://threatfox.abuse.ch/export/json/ip-port/recent/", ThreatFeedFormat.ThreatFoxJson,
            TimeSpan.FromHours(1), OnByDefault: false,
            "Command-and-control servers of current malware, reported in the last two days; DG SIEM keeps each for 30 days after it was last seen.",
            "https://abuse.ch/terms-of-use/",
            Caution: "abuse.ch's terms say commercial use may need a paid subscription (through Spamhaus). Check before using it for clients.",
            KeepDays: 30),
        new("tor-exits", "Tor exit nodes", "https://check.torproject.org/torbulkexitlist", ThreatFeedFormat.PlainText,
            TimeSpan.FromHours(6), OnByDefault: false,
            "Addresses traffic leaves the Tor network from. Not malicious in itself, but a sign-in from one is worth a look.",
            "https://www.torproject.org/", EntryDescription: "Tor exit node"),
    ];

    /// <summary>Reads a downloaded feed into indicators. Throws <see cref="FormatException"/> when it isn't the expected format.</summary>
    public static List<ThreatIndicator> Parse(ThreatFeedFormat format, string content, string feedName, string plainDescription = "Listed")
    {
        ArgumentNullException.ThrowIfNull(content);
        try
        {
            return format switch
            {
                ThreatFeedFormat.SpamhausDrop => SpamhausDrop(content, feedName),
                ThreatFeedFormat.FeodoJson => Feodo(content, feedName),
                ThreatFeedFormat.ThreatFoxJson => ThreatFox(content, feedName),
                _ => PlainText(content, feedName, plainDescription),
            };
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Not the expected format: {ex.Message}", ex);
        }
    }

    /// <summary>One address or range per line (your list, custom feeds, Tor). Lines that aren't one are skipped.</summary>
    public static List<ThreatIndicator> PlainText(string content, string feedName, string description)
    {
        var list = new List<ThreatIndicator>();
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';' || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }
            var value = line.Split([' ', '\t', ',', ';', '#'], 2, StringSplitOptions.RemoveEmptyEntries)[0];
            if (ThreatIndex.TryParse(value, out _, out _))
            {
                list.Add(new ThreatIndicator(value, feedName, description));
            }
        }
        return list;
    }

    private static List<ThreatIndicator> SpamhausDrop(string content, string feedName)
    {
        var list = new List<ThreatIndicator>();
        foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.TryGetProperty("type", out _))
            {
                continue; // the metadata line
            }
            if (root.TryGetProperty("cidr", out var cidr) && cidr.GetString() is { } value)
            {
                var sbl = root.TryGetProperty("sblid", out var id) ? id.GetString() : null;
                list.Add(new ThreatIndicator(value, feedName, sbl is null ? "Listed on DROP" : $"Listed on DROP ({sbl})"));
            }
        }
        if (list.Count == 0 && content.Length > 0 && !content.TrimStart().StartsWith('{'))
        {
            throw new FormatException("Not a DROP JSON file.");
        }
        return list;
    }

    private static List<ThreatIndicator> Feodo(string content, string feedName)
    {
        using var doc = JsonDocument.Parse(content);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("Expected a JSON array.");
        }
        var list = new List<ThreatIndicator>();
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            if (Str(e, "ip_address") is not { } ip)
            {
                continue;
            }
            var malware = Str(e, "malware") ?? "unknown malware";
            var status = Str(e, "status");
            list.Add(new ThreatIndicator(ip, feedName, $"Botnet C2: {malware}{(status is null ? "" : $" ({status})")}"));
        }
        return list;
    }

    private static List<ThreatIndicator> ThreatFox(string content, string feedName)
    {
        using var doc = JsonDocument.Parse(content);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("Expected a JSON object of IOCs.");
        }
        var list = new List<ThreatIndicator>();
        foreach (var ioc in doc.RootElement.EnumerateObject())
        {
            if (ioc.Value.ValueKind != JsonValueKind.Array)
            {
                continue;
            }
            foreach (var e in ioc.Value.EnumerateArray())
            {
                if (Str(e, "ioc_value") is not { } value || Address(value) is not { } ip)
                {
                    continue;
                }
                var malware = Str(e, "malware_printable") ?? Str(e, "malware") ?? "unknown malware";
                var kind = Str(e, "threat_type") == "botnet_cc" ? "C2" : Str(e, "threat_type") ?? "IOC";
                var seen = Time(Str(e, "last_seen_utc")) ?? Time(Str(e, "first_seen_utc"));
                list.Add(new ThreatIndicator(ip, feedName, $"{kind}: {malware}", seen));
            }
        }
        return list;
    }

    /// <summary>The address of <c>1.2.3.4:443</c>, <c>[2001:db8::1]:443</c> or a bare address.</summary>
    private static string? Address(string value)
    {
        var v = value.Trim();
        if (v.StartsWith('['))
        {
            var close = v.IndexOf(']', StringComparison.Ordinal);
            return close > 1 ? v[1..close] : null;
        }
        var colon = v.LastIndexOf(':');
        var candidate = colon > 0 && v.IndexOf(':', StringComparison.Ordinal) == colon ? v[..colon] : v;
        return ThreatIndex.TryParse(candidate, out _, out _) ? candidate : null;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String && p.GetString() is { Length: > 0 } s ? s : null;

    private static DateTimeOffset? Time(string? text) =>
        text is not null && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;
}
