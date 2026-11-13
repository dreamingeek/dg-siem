using System.Globalization;
using System.Net;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers.Formats;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// UniFi gateways and consoles. Handles:
/// <list type="bullet">
/// <item>CEF from UniFi Network's SIEM integration (<c>CEF:0|Ubiquiti|UniFi Network|…</c>) → <c>unifi.&lt;category&gt;</c></item>
/// <item>Legacy netfilter firewall lines (<c>[WAN_IN-D-3000] IN=… SRC=… DST=…</c>) → <c>unifi.firewall</c></item>
/// <item>strongSwan IPsec → <c>unifi.vpn</c>; DHCP server lines → <c>unifi.dhcp</c></item>
/// <item>AP / switch lines → <c>unifi.ap</c> / <c>unifi.switch</c> (Wi-Fi client events get client.mac/ip)</item>
/// <item>DPI → <c>unifi.dpi</c>; anything else from a source tagged <c>unifi</c> → <c>unifi.system</c></item>
/// </list>
/// Untagged CEF from Ubiquiti is recognised on its own; legacy lines need the agent's source hint
/// (<c>dataset: unifi</c>) because plain iptables lines look the same from any Linux box.
/// </summary>
public sealed class UnifiParser : IEventParser
{
    public const string Module = "unifi";

    public string Dataset => "unifi";
    public int Priority => 100;

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return string.Equals(envelope.DatasetHint, Module, StringComparison.OrdinalIgnoreCase) ||
               envelope.Message.Contains("CEF:0|Ubiquiti|", StringComparison.Ordinal);
    }

    public bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var hasHeader = SyslogParser.TryParseHeader(envelope.Message, envelope.ReceivedAt, out var header);
        var body = hasHeader ? header.Message : envelope.Message;

        var e = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = hasHeader ? header.Timestamp : envelope.ReceivedAt,
            HostName = hasHeader ? header.Hostname : string.Empty,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventModule = Module,
            LogLevel = hasHeader ? SyslogParser.SeverityName(header.Severity) : string.Empty,
            Message = body,
            Raw = envelope.Message,
        };
        e.Fields["observer.vendor"] = "Ubiquiti";
        if (hasHeader && header.TimeZoneOffset is { } offset)
        {
            e.Fields["event.timezone"] = SyslogParser.FormatOffset(offset);
        }
        if (hasHeader && header.AppName.Length > 0)
        {
            body = ApplyTag(header.AppName, body, e);
            e.Message = body;
        }
        if (hasHeader && header.ProcId.Length > 0)
        {
            e.Fields["process.pid"] = header.ProcId;
        }

        if (Cef.TryParse(envelope.Message, out var cef) && cef is not null)
        {
            MapCef(cef, e);
        }
        else if (KernelFirewall.Looks(body))
        {
            MapFirewall(KernelFirewall.Parse(body), e);
        }
        else if (IsIpsec(e, body))
        {
            e.EventDataset = "unifi.vpn";
            e.Fields["event.category"] = "network";
        }
        else if (TryMapDhcp(body, e))
        {
            e.EventDataset = "unifi.dhcp";
        }
        else
        {
            e.EventDataset = DeviceDataset(e) ?? (ProcessIs(e, "ubnt-dpi-util", "dpi-flow-stats") ? "unifi.dpi" : "unifi.system");
            TryMapWireless(body, e);
        }

        logEvent = e;
        return true;
    }

    private static bool ProcessIs(LogEvent e, params string[] names) =>
        e.Fields.TryGetValue("process.name", out var p) && names.Contains(p, StringComparer.Ordinal);

    /// <summary>
    /// Lines from an AP or switch (tagged "mac,model-version") go to unifi.ap / unifi.switch by model,
    /// e.g. U7-Pro → ap, USW-24-PoE → switch. Unknown models → unifi.device.
    /// </summary>
    internal static string? DeviceDataset(LogEvent e)
    {
        if (!e.Fields.TryGetValue("observer.mac", out _) || !e.Fields.TryGetValue("observer.product", out var model))
        {
            return null;
        }
        string[] aps = ["U6", "U7", "UAP", "UAL", "UK-", "UK ", "E7", "ULR", "UWB", "UMR", "UBB", "AC-", "BZ2", "U2"];
        string[] switches = ["USW", "US-", "US8", "US16", "US24", "US48", "USL", "USF", "USP", "ECS", "EFG"];
        if (aps.Any(p => model.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            e.Fields["observer.type"] = "access-point";
            return "unifi.ap";
        }
        if (switches.Any(p => model.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            e.Fields["observer.type"] = "switch";
            return "unifi.switch";
        }
        return "unifi.device";
    }

    private static readonly System.Text.RegularExpressions.Regex DhcpLine = new(
        @"^DHCP(?<type>[A-Z]+)\((?<iface>[^)]+)\)\s+(?:(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+)?(?<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:\s+(?<name>\S+))?",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.ExplicitCapture,
        TimeSpan.FromMilliseconds(50));

    /// <summary><c>DHCPACK(br0) 10.1.1.200 02:00:5e:10:00:04 LAPTOP-01</c> → action, client ip/mac/hostname, interface.</summary>
    private static bool TryMapDhcp(string body, LogEvent e)
    {
        var m = DhcpLine.Match(body);
        if (!m.Success)
        {
            return false;
        }
        e.EventAction = "dhcp" + m.Groups["type"].Value.ToLowerInvariant();
        e.Fields["event.category"] = "network";
        e.Fields["observer.ingress.interface.name"] = m.Groups["iface"].Value;
        e.Fields["client.mac"] = EcsMac(m.Groups["mac"].Value);
        if (m.Groups["ip"].Success)
        {
            e.Fields["client.ip"] = m.Groups["ip"].Value;
        }
        if (m.Groups["name"].Success)
        {
            e.Fields["unifi.dhcp.hostname"] = m.Groups["name"].Value;
        }
        return true;
    }

    private static readonly System.Text.RegularExpressions.Regex StaEvent = new(
        @"EVENT_(?<event>STA_[A-Z_]+)\s+(?<iface>\S+):\s+(?<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:\s*/\s*(?<extra>\S+))?",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.ExplicitCapture,
        TimeSpan.FromMilliseconds(50));

    private static readonly System.Text.RegularExpressions.Regex StaMac = new(
        @"\bSTA (?<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.ExplicitCapture,
        TimeSpan.FromMilliseconds(50));

    /// <summary>
    /// Wi-Fi client events: <c>EVENT_STA_JOIN wifi0ap5: 94:b5:… / 5</c>, <c>EVENT_STA_IP …: mac / 10.1.1.200</c>,
    /// <c>STA 94:b5:… WPA: … roamed</c> → event.action (sta_join, sta_ip, …), client.mac, client.ip.
    /// </summary>
    private static void TryMapWireless(string body, LogEvent e)
    {
        var m = StaEvent.Match(body);
        if (m.Success)
        {
            e.EventAction = m.Groups["event"].Value.ToLowerInvariant();
            e.Fields["client.mac"] = EcsMac(m.Groups["mac"].Value);
            e.Fields["observer.ingress.interface.name"] = m.Groups["iface"].Value;
            if (m.Groups["extra"].Success && System.Net.IPAddress.TryParse(m.Groups["extra"].Value, out var ip))
            {
                e.Fields["client.ip"] = ip.ToString();
            }
            return;
        }
        var sta = StaMac.Match(body);
        if (sta.Success)
        {
            e.Fields["client.mac"] = EcsMac(sta.Groups["mac"].Value);
            if (body.Contains("roamed", StringComparison.OrdinalIgnoreCase))
            {
                e.EventAction = "sta_roam";
            }
            else if (body.Contains("associated", StringComparison.OrdinalIgnoreCase))
            {
                e.EventAction = body.Contains("disassociated", StringComparison.OrdinalIgnoreCase) ? "sta_disassociate" : "sta_associate";
            }
        }
    }

    /// <summary>ECS MAC format: uppercase, dash-separated.</summary>
    private static string EcsMac(string mac) => mac.Replace(':', '-').ToUpperInvariant();

    private static readonly string[] IpsecSubsystems = ["IKE", "ENC", "NET", "CFG", "CHD", "KNL", "JOB", "MGR", "LIB", "ESP", "DMN", "ASN", "TNC", "IMC", "IMV", "PTS", "TLS", "APP"];

    /// <summary>
    /// strongSwan (IPsec) lines, logged by <c>charon</c> or UniFi's <c>ubios-udapi-server</c>:
    /// <c>14[ENC] parsed QUICK_MODE request ...</c>. Tagged so the chatty keepalives are easy to filter.
    /// </summary>
    private static bool IsIpsec(LogEvent e, string body)
    {
        var process = e.Fields.GetValueOrDefault("process.name");
        if (process is not ("charon" or "ubios-udapi-server" or "ipsec" or "swanctl"))
        {
            return false;
        }
        var open = body.IndexOf('[', StringComparison.Ordinal);
        if (open is < 1 or > 3 || body.Length < open + 5 || body[open + 4] != ']' || !body[..open].All(char.IsAsciiDigit))
        {
            return false;
        }
        var subsystem = body.Substring(open + 1, 3);
        if (Array.IndexOf(IpsecSubsystems, subsystem) < 0)
        {
            return false;
        }
        e.Fields["unifi.ipsec.subsystem"] = subsystem;
        if (body.Contains("DPD", StringComparison.Ordinal))
        {
            e.EventAction = "ipsec_keepalive";
        }
        return true;
    }

    /// <summary>UniFi CEF keys that map onto ECS fields (the rest are kept as unifi.*).</summary>
    private static readonly Dictionary<string, string> MappedUnifiKeys = new(StringComparer.Ordinal)
    {
        ["UNIFIsrcClientIp"] = "source.ip",
        ["UNIFIsrcClientMac"] = "source.mac",
        ["UNIFIsrcClientHostname"] = "source.domain",
        ["UNIFIsrcClientAlias"] = "source.alias",
        ["UNIFIsrcClientModel"] = "source.device.model",
        ["UNIFIsrcZone"] = "observer.ingress.zone",
        ["UNIFIdstClientIp"] = "destination.ip",
        ["UNIFIdstClientMac"] = "destination.mac",
        ["UNIFIdstClientHostname"] = "destination.domain",
        ["UNIFIdstClientAlias"] = "destination.alias",
        ["UNIFIdstZone"] = "observer.egress.zone",
        ["UNIFIdstRegion"] = "destination.geo.country_iso_code",
        ["UNIFIsrcRegion"] = "source.geo.country_iso_code",
        ["UNIFIclientIp"] = "client.ip",
        ["UNIFIclientMac"] = "client.mac",
        ["UNIFIclientHostname"] = "client.domain",
        ["UNIFIclientAlias"] = "client.alias",
        ["deviceInboundInterface"] = "observer.ingress.interface.name",
        ["deviceOutboundInterface"] = "observer.egress.interface.name",
        ["UNIFItotalBytes"] = "network.bytes",
        ["UNIFItotalPackets"] = "network.packets",
        ["UNIFIdirection"] = "network.direction",
        ["app"] = "network.protocol",
        ["UNIFIfirewallPolicy"] = "rule.name",
        ["UNIFIpolicyName"] = "rule.name",
        ["UNIFIpolicyType"] = "rule.category",
        ["UNIFIrisk"] = "event.risk",
    };

    /// <summary>Maps UniFi's client/zone/interface CEF keys to ECS; promoted columns get their own properties.</summary>
    private static void MapUnifiEndpoints(IReadOnlyDictionary<string, string> x, LogEvent e)
    {
        foreach (var (key, field) in MappedUnifiKeys)
        {
            if (Get(x, key) is not { } value || value is "null")
            {
                continue;
            }
            switch (field)
            {
                case "source.ip" when e.SourceIp.Length == 0:
                    e.SourceIp = Ip(value) ?? string.Empty;
                    break;
                case "destination.ip" when e.DestinationIp.Length == 0:
                    e.DestinationIp = Ip(value) ?? string.Empty;
                    break;
                case "source.ip" or "destination.ip":
                    break;
                case "network.protocol":
                    e.NetworkProtocol = value.ToLowerInvariant();
                    break;
                case "network.direction":
                    // ECS values: outgoing → outbound, incoming → inbound.
                    e.Fields[field] = value.ToLowerInvariant() switch
                    {
                        "outgoing" or "outbound" or "egress" => "outbound",
                        "incoming" or "inbound" or "ingress" => "inbound",
                        "internal" or "local" => "internal",
                        var other => other,
                    };
                    break;
                case "source.mac" or "destination.mac" or "client.mac":
                    e.Fields[field] = EcsMac(value);
                    break;
                default:
                    e.Fields.TryAdd(field, value);
                    break;
            }
        }
    }

    /// <summary>
    /// UniFi APs and switches tag lines with <c>mac,model-version</c> (e.g. <c>942a6fc2c4dc,U7-Pro-8.8.14+20179</c>)
    /// and put the real process in the message (<c>hostapd: ...</c>). Split both out; plain tags pass through.
    /// </summary>
    internal static string ApplyTag(string tag, string message, LogEvent e)
    {
        var comma = tag.IndexOf(',', StringComparison.Ordinal);
        if (comma != 12 || !tag[..12].All(Uri.IsHexDigit))
        {
            e.Fields["process.name"] = tag;
            return message;
        }

        var mac = tag[..12].ToUpperInvariant();
        e.Fields["observer.mac"] = string.Join('-', Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2)));
        var modelAndVersion = tag[(comma + 1)..];
        var split = VersionStart(modelAndVersion);
        if (split > 0)
        {
            e.Fields["observer.product"] = modelAndVersion[..split];
            e.Fields["observer.version"] = modelAndVersion[(split + 1)..];
        }
        else
        {
            e.Fields["observer.product"] = modelAndVersion;
        }

        // The real process: "hostapd: ath0: ..." or "kernel: [..." at the start of the message.
        var colon = message.IndexOf(": ", StringComparison.Ordinal);
        if (colon > 0 && colon < 48 && !message[..colon].Contains(' ', StringComparison.Ordinal))
        {
            var process = message[..colon];
            var bracket = process.IndexOf('[', StringComparison.Ordinal);
            if (bracket > 0 && process.EndsWith(']'))
            {
                e.Fields["process.pid"] = process[(bracket + 1)..^1];
                process = process[..bracket];
            }
            e.Fields["process.name"] = process;
            return message[(colon + 2)..];
        }
        return message;
    }

    /// <summary>Index of the '-' that starts the firmware version in <c>U7-Pro-8.8.14+20179</c>, or -1.</summary>
    private static int VersionStart(string modelAndVersion)
    {
        for (var i = modelAndVersion.Length - 2; i > 0; i--)
        {
            if (modelAndVersion[i] == '-' && char.IsAsciiDigit(modelAndVersion[i + 1]) && modelAndVersion[(i + 1)..].Contains('.', StringComparison.Ordinal))
            {
                return i;
            }
        }
        return -1;
    }

    private static void MapCef(CefRecord cef, LogEvent e)
    {
        var x = cef.Extensions;
        var category = Get(x, "UNIFIcategory");
        var subCategory = Get(x, "UNIFIsubCategory");
        // UniFi OS (console-level) events carry no category; name them after the product instead.
        e.EventDataset = "unifi." + Slug(category ?? (cef.DeviceProduct.Equals("UniFi OS", StringComparison.OrdinalIgnoreCase) ? "os" : "cef"));
        // Firewall hits arrive as category Security with a firewall policy ("Blocked by Firewall");
        // file them with the iptables-style lines so one dataset covers both formats.
        var isFirewall =
            string.Equals(subCategory, "Firewall", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(category, "Firewall", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Get(x, "UNIFIpolicyType"), "Firewall", StringComparison.OrdinalIgnoreCase) ||
            Get(x, "UNIFIfirewallPolicy") is not null ||
            cef.Name.Contains("by Firewall", StringComparison.OrdinalIgnoreCase);
        if (isFirewall)
        {
            e.EventDataset = "unifi.firewall";
            e.Fields["event.category"] = "network";
            if ((Get(x, "UNIFIfirewallPolicy") ?? Get(x, "UNIFIpolicyName")) is { } policy)
            {
                e.Fields["rule.name"] = policy;
            }
        }
        e.EventAction = Slug(cef.Name);
        e.Message = Get(x, "msg") ?? cef.Name;
        e.Fields["event.code"] = cef.SignatureId;
        e.Fields["event.severity"] = cef.Severity;
        e.Fields["observer.product"] = cef.DeviceProduct;
        e.Fields["observer.version"] = cef.DeviceVersion;
        if (subCategory is not null)
        {
            e.Fields["unifi.sub_category"] = subCategory;
        }

        e.SourceIp = Ip(Get(x, "src")) ?? e.SourceIp;
        e.DestinationIp = Ip(Get(x, "dst")) ?? e.DestinationIp;
        e.SourcePort = Port(Get(x, "spt"));
        e.DestinationPort = Port(Get(x, "dpt"));
        e.NetworkTransport = Get(x, "proto")?.ToLowerInvariant() ?? string.Empty;
        e.UserName = Get(x, "suser") ?? Get(x, "duser") ?? Get(x, "UNIFIadmin") ?? string.Empty;
        // Action: the CEF act field, or the event name's verb ("Blocked by Firewall" → blocked).
        var action = Get(x, "act")?.ToLowerInvariant()
            ?? (cef.Name.StartsWith("Blocked", StringComparison.OrdinalIgnoreCase) ? "blocked"
              : cef.Name.StartsWith("Allowed", StringComparison.OrdinalIgnoreCase) ? "allowed" : null);
        if (action is not null)
        {
            e.EventAction = action;
            e.Fields["event.type"] = action is "block" or "blocked" or "drop" or "dropped" or "deny" or "denied" or "reject" or "rejected"
                ? "denied"
                : action is "allow" or "allowed" or "accept" or "accepted" or "pass" ? "allowed" : action;
        }

        MapUnifiEndpoints(x, e);
        if (Get(x, "UNIFIhost") is { } unifiHost && e.HostName.Length == 0)
        {
            e.HostName = unifiHost;
        }
        if (Get(x, "UNIFIdeviceName") is { } deviceName)
        {
            e.Fields["observer.name"] = deviceName;
            if (e.HostName.Length == 0)
            {
                e.HostName = deviceName;
            }
        }

        // Exact UTC time with milliseconds, better than the syslog header's second-resolution local time.
        if (Get(x, "UNIFIutcTime") is { } utc &&
            DateTimeOffset.TryParse(utc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var utcTime))
        {
            e.Timestamp = utcTime;
        }

        // Admin-access events only give the client address inside the message text.
        if (e.SourceIp.Length == 0 && e.Message.LastIndexOf("Source IP: ", StringComparison.Ordinal) is var at and >= 0 &&
            Ip(e.Message[(at + "Source IP: ".Length)..].Trim().TrimEnd('.')) is { } fromMessage)
        {
            e.SourceIp = fromMessage;
        }
        if (Get(x, "dvchost") is { } dvcHost && e.HostName.Length == 0)
        {
            e.HostName = dvcHost;
        }

        // Everything else is kept: UniFi-specific keys as unifi.<key>, standard CEF keys as cef.<key>.
        foreach (var (key, value) in x)
        {
            if (key is "src" or "dst" or "spt" or "dpt" or "proto" or "msg" or "suser" or "duser" or "act" or "UNIFIcategory" or "UNIFIsubCategory" ||
                MappedUnifiKeys.ContainsKey(key))
            {
                continue;
            }
            var name = key.StartsWith("UNIFI", StringComparison.Ordinal)
                ? "unifi." + ToSnake(key["UNIFI".Length..])
                : "cef." + key;
            e.Fields[name] = value;
        }
    }

    private static void MapFirewall(KernelFirewallRecord fw, LogEvent e)
    {
        var f = fw.Fields;
        e.EventDataset = "unifi.firewall";
        e.Fields["event.category"] = "network";
        e.SourceIp = Ip(Get(f, "SRC")) ?? string.Empty;
        e.DestinationIp = Ip(Get(f, "DST")) ?? string.Empty;
        e.SourcePort = KernelFirewall.Port(f, "SPT");
        e.DestinationPort = KernelFirewall.Port(f, "DPT");
        e.NetworkTransport = Get(f, "PROTO")?.ToLowerInvariant() ?? string.Empty;

        var action = KernelFirewall.ActionFromRule(fw.Rule);
        if (action is not null)
        {
            e.EventAction = action;
            e.Fields["event.type"] = action is "accept" or "return" ? "allowed" : "denied";
        }
        if (fw.Rule is not null)
        {
            e.Fields["rule.name"] = fw.Rule;
        }
        if (Get(f, "DESCR") is { Length: > 0 } descr)
        {
            e.Fields["rule.description"] = descr;
        }
        if (Get(f, "IN") is { Length: > 0 } inIf)
        {
            e.Fields["observer.ingress.interface.name"] = inIf;
        }
        if (Get(f, "OUT") is { Length: > 0 } outIf)
        {
            e.Fields["observer.egress.interface.name"] = outIf;
        }
        if (Get(f, "MAC") is { Length: > 0 } mac)
        {
            e.Fields["unifi.mac"] = mac;
        }
        if (Get(f, "LEN") is { } len)
        {
            e.Fields["network.bytes"] = len;
        }
        if (fw.Flags.Count > 0)
        {
            e.Fields["unifi.tcp_flags"] = string.Join(' ', fw.Flags.Where(IsTcpFlag));
        }
    }

    private static bool IsTcpFlag(string flag) => flag is "SYN" or "ACK" or "FIN" or "RST" or "PSH" or "URG" or "CWR" or "ECE";

    private static string? Get(IReadOnlyDictionary<string, string> d, string key) =>
        d.TryGetValue(key, out var v) && v.Length > 0 ? v : null;

    private static string? Ip(string? value) => value is not null && IPAddress.TryParse(value, out var ip) ? ip.ToString() : null;

    private static ushort Port(string? value) =>
        ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : (ushort)0;

    /// <summary><c>"Admin Accessed UniFi Network"</c> → <c>admin_accessed_unifi_network</c>.</summary>
    internal static string Slug(string text)
    {
        var chars = text.Trim().ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_').ToArray();
        return string.Join('_', new string(chars).Split('_', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary><c>accessMethod</c> → <c>access_method</c>.</summary>
    private static string ToSnake(string key)
    {
        var sb = new System.Text.StringBuilder(key.Length + 8);
        for (var i = 0; i < key.Length; i++)
        {
            var c = key[i];
            if (char.IsUpper(c) && i > 0 && !char.IsUpper(key[i - 1]))
            {
                sb.Append('_');
            }
            sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }
}
