using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// Asterisk (FreePBX) logs: the <c>full</c> / <c>security</c> files (tailed by the agent or forwarded by rsyslog's
/// imfile) and Asterisk's own syslog channel. Lines look like
/// <c>[2026-11-12 10:31:16] NOTICE[1559][C-0000001a] res_pjsip/pjsip_distributor.c: message</c>.
/// <list type="bullet">
/// <item><c>asterisk.security</c>: failed SIP requests (bad password, unknown account, ACL) and the security
/// log's <c>SecurityEvent=</c> lines. These are what brute-force alerts are built on.</item>
/// <item><c>asterisk.registration</c>: contacts added/removed, endpoints reachable/unreachable.</item>
/// <item><c>asterisk.sip</c>: packets from <c>pjsip set logger on</c> (one event per packet with the file input's
/// <c>Pattern</c> multiline mode), with method, status, Call-ID, From/To and the phone's User-Agent.</item>
/// <item><c>asterisk.call</c>: dialplan steps and Dial progress; <c>asterisk.log</c> for everything else.</item>
/// </list>
/// Asterisk writes local time without a zone; the agent's header carries the host's offset, otherwise the
/// offset is worked out from when the line arrived.
/// </summary>
public sealed partial class AsteriskParser : IEventParser
{
    public const string Module = "asterisk";
    public const string LogDataset = "asterisk.log";
    public const string SecurityDataset = "asterisk.security";
    public const string RegistrationDataset = "asterisk.registration";
    public const string SipDataset = "asterisk.sip";
    public const string CallDataset = "asterisk.call";

    public string Dataset => LogDataset;
    public int Priority => 80;

    private static readonly string[] Levels = ["VERBOSE[", "NOTICE[", "WARNING[", "ERROR[", "SECURITY[", "DEBUG[", "DTMF["];

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var m = envelope.Message.AsSpan(0, Math.Min(envelope.Message.Length, 256));
        foreach (var level in Levels)
        {
            if (m.Contains(level, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    // [2026-11-12 10:31:16] or [Nov 12 10:31:16], then LEVEL[lwp][C-callid], then file.c[:line][ in func]: message.
    [GeneratedRegex(
        @"^(?:\[(?<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d(?:\.\d+)?)\]\s+)?" +
        @"(?<level>VERBOSE|NOTICE|WARNING|ERROR|SECURITY|DEBUG|DTMF)\[(?<lwp>\d+)\](?:\[(?<call>C-[0-9A-Fa-f]+)\])?:?\s+" +
        @"(?<file>[\w./-]+\.c)(?::(?<line>\d+))?(?: in (?<func>\w+))?:\s(?<msg>.*)$",
        RegexOptions.Singleline | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex LineRegex();

    public bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        logEvent = null;
        var hasHeader = SyslogParser.TryParseHeader(envelope.Message, envelope.ReceivedAt, out var header);
        var body = hasHeader ? header.Message : envelope.Message;
        Match m;
        try
        {
            m = LineRegex().Match(body);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        if (!m.Success)
        {
            return false;
        }

        var level = m.Groups["level"].Value;
        var file = m.Groups["file"].Value;
        var message = Unprefix(m.Groups["msg"].Value.TrimEnd());
        var e = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = Time(m.Groups["ts"], hasHeader ? header : null, envelope.ReceivedAt, out var zone),
            HostName = hasHeader ? header.Hostname : string.Empty,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventDataset = LogDataset,
            EventModule = Module,
            LogLevel = level switch
            {
                "ERROR" => "error",
                "WARNING" => "warning",
                "NOTICE" or "SECURITY" => "notice",
                "DEBUG" => "debug",
                _ => "informational",
            },
            Message = message,
            Raw = envelope.Message,
        };
        e.Fields["log.origin.file.name"] = file;
        e.Fields["process.thread.id"] = m.Groups["lwp"].Value;
        if (m.Groups["line"].Success)
        {
            e.Fields["log.origin.file.line"] = m.Groups["line"].Value;
        }
        if (m.Groups["func"].Success)
        {
            e.Fields["log.origin.function"] = m.Groups["func"].Value;
        }
        if (m.Groups["call"].Success)
        {
            e.Fields["asterisk.call_id"] = m.Groups["call"].Value;
        }
        if (zone is { } offset)
        {
            e.Fields["event.timezone"] = SyslogParser.FormatOffset(offset);
        }

        try
        {
            var recognised = (message.Contains("SecurityEvent=\"", StringComparison.Ordinal) && SecurityEvent(message, e))
                || (file.EndsWith("res_pjsip_logger.c", StringComparison.Ordinal) && SipPacket(message, e))
                || FailedRequest(message, e)
                || Registration(message, e)
                || Call(message, e);
            if (!recognised && e.LogLevel is "warning" or "error")
            {
                e.EventOutcome = "failure";
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // Keep the generic event.
        }
        logEvent = e;
        return true;
    }

    /// <summary>Verbose output is indented and marked by level: <c>    -- Called PJSIP/115</c>, <c>  == Using SIP RTP</c>.</summary>
    private static string Unprefix(string message)
    {
        var text = message.TrimStart(' ', '\t');
        foreach (var marker in (string[])["-- ", "== ", "> "])
        {
            if (text.StartsWith(marker, StringComparison.Ordinal))
            {
                return text[marker.Length..];
            }
        }
        return text;
    }

    // ---- Time --------------------------------------------------------------------------------

    private static DateTimeOffset Time(Group ts, SyslogParser.SyslogHeader? header, DateTimeOffset receivedAt, out TimeSpan? zone) =>
        LocalTime.Resolve(ts.Success ? ts.Value : string.Empty, header, receivedAt, out zone);

    // ---- Security log ------------------------------------------------------------------------

    [GeneratedRegex(@"(?<k>\w+)=""(?<v>(?:[^""\\]|\\.)*)""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex KeyValueRegex();

    /// <summary>Values that are challenge/response material, not useful to search and best not stored.</summary>
    private static readonly HashSet<string> SecretKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Challenge", "ReceivedChallenge", "ReceivedHash", "Response", "ExpectedResponse", "ReceivedHashEncoded",
    };

    /// <summary><c>SecurityEvent="InvalidPassword",EventTV="...",Service="PJSIP",AccountID="114",RemoteAddress="IPV4/UDP/1.2.3.4/5060",...</c></summary>
    private static bool SecurityEvent(string message, LogEvent e)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match kv in KeyValueRegex().Matches(message))
        {
            values[kv.Groups["k"].Value] = kv.Groups["v"].Value;
        }
        if (!values.TryGetValue("SecurityEvent", out var name))
        {
            return false;
        }
        e.EventDataset = SecurityDataset;
        e.EventAction = Kebab(name);
        e.EventOutcome = name switch
        {
            "SuccessfulAuth" => "success",
            "ChallengeSent" => "unknown",
            _ => "failure",
        };
        e.Fields["event.kind"] = "event";
        e.Fields["event.category"] = "authentication";
        if (values.TryGetValue("EventTV", out var tv) && ParseEventTime(tv) is { } time)
        {
            e.Timestamp = time;
        }
        if (values.TryGetValue("AccountID", out var account) && account.Length > 0)
        {
            e.UserName = UriUser(account) ?? account;
        }
        if (values.TryGetValue("RemoteAddress", out var remote) && Address(remote) is { } r)
        {
            e.SourceIp = r.Ip;
            e.SourcePort = r.Port;
            e.NetworkTransport = r.Transport;
        }
        if (values.TryGetValue("LocalAddress", out var local) && Address(local) is { } l)
        {
            e.DestinationIp = l.Ip;
            e.DestinationPort = l.Port;
        }
        if (values.TryGetValue("SessionID", out var session) && session.Length > 0)
        {
            e.Fields["sip.call_id"] = session;
        }
        e.NetworkProtocol = values.TryGetValue("Service", out var service) && service.Contains("SIP", StringComparison.OrdinalIgnoreCase) ? "sip" : string.Empty;
        foreach (var (key, value) in values)
        {
            if (value.Length > 0 && !SecretKeys.Contains(key) && key is not ("SecurityEvent" or "EventTV" or "AccountID" or "RemoteAddress" or "LocalAddress" or "SessionID"))
            {
                e.Fields[$"asterisk.security.{Snake(key)}"] = value;
            }
        }
        e.Message = $"{name}{(e.UserName.Length > 0 ? $" for {e.UserName}" : "")}{(e.SourceIp.Length > 0 ? $" from {e.SourceIp}" : "")}";
        return true;
    }

    /// <summary><c>2026-11-12T10:31:16.123-0600</c> (Asterisk's EventTV).</summary>
    private static DateTimeOffset? ParseEventTime(string value)
    {
        // "-0600" → "-06:00" so the standard parser takes it.
        if (value.Length > 5 && value[^5] is '+' or '-' && value[^4..].All(char.IsAsciiDigit))
        {
            value = value.Insert(value.Length - 2, ":");
        }
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var t) ? t.ToUniversalTime() : null;
    }

    /// <summary><c>IPV4/UDP/1.2.3.4/5060</c> or <c>IPV6/TLS/2001:db8::1/5061</c>.</summary>
    private static (string Ip, ushort Port, string Transport)? Address(string value)
    {
        var parts = value.Split('/');
        if (parts.Length < 4 || !IPAddress.TryParse(parts[2], out var ip))
        {
            return null;
        }
        ushort.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var port);
        return (ip.ToString(), port, parts[1].ToLowerInvariant());
    }

    // ---- Failed requests ---------------------------------------------------------------------

    // PJSIP: Request 'REGISTER' from '"114" <sip:114@host>' failed for '1.2.3.4:5060' (callid: abc) - Failed to authenticate
    // chan_sip: Registration from '"101" <sip:101@host>' failed for '1.2.3.4:5060' - Wrong password
    [GeneratedRegex(
        @"^(?:Request '(?<method>[A-Z]+)' from|Registration from) '(?<from>.*?)' failed for '(?<addr>[^']+)'(?: \(callid: (?<callid>[^)]*)\))? - (?<reason>.+)$",
        RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex FailedRegex();

    private static bool FailedRequest(string message, LogEvent e)
    {
        var m = FailedRegex().Match(message);
        if (!m.Success)
        {
            return false;
        }
        var reason = m.Groups["reason"].Value.Trim();
        e.EventDataset = SecurityDataset;
        e.EventAction = reason switch
        {
            _ when reason.Contains("authenticate", StringComparison.OrdinalIgnoreCase) || reason.Contains("password", StringComparison.OrdinalIgnoreCase) => "auth-failed",
            _ when reason.Contains("No matching", StringComparison.OrdinalIgnoreCase) || reason.Contains("mismatch", StringComparison.OrdinalIgnoreCase) => "unknown-account",
            _ when reason.Contains("ACL", StringComparison.Ordinal) => "acl-denied",
            _ => "request-rejected",
        };
        e.EventOutcome = "failure";
        e.NetworkProtocol = "sip";
        e.Fields["event.kind"] = "event";
        e.Fields["event.category"] = "authentication";
        e.Fields["sip.method"] = m.Groups["method"].Success ? m.Groups["method"].Value : "REGISTER";
        e.Fields["asterisk.reason"] = reason;
        if (m.Groups["callid"].Success && m.Groups["callid"].Value.Length > 0)
        {
            e.Fields["sip.call_id"] = m.Groups["callid"].Value;
        }
        var from = m.Groups["from"].Value;
        if (UriUser(from) is { } user)
        {
            e.UserName = user;
        }
        if (Display(from) is { } display)
        {
            e.Fields["sip.from.display"] = display;
        }
        if (HostPort(m.Groups["addr"].Value) is { } addr)
        {
            e.SourceIp = addr.Ip;
            e.SourcePort = addr.Port;
        }
        return true;
    }

    // ---- Registrations -----------------------------------------------------------------------

    [GeneratedRegex(@"^Added contact '(?<contact>[^']+)' to AOR '(?<aor>[^']+)' with expiration of (?<expires>\d+) seconds", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex AddedRegex();

    [GeneratedRegex(@"^Removed contact '(?<contact>[^']+)' from AOR '(?<aor>[^']+)'(?: due to (?<reason>.+))?$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex RemovedRegex();

    [GeneratedRegex(@"^Endpoint (?<endpoint>\S+) is now (?<state>\w+)", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex EndpointRegex();

    [GeneratedRegex(@"^Contact (?<aor>[^/\s]+)/(?<contact>\S+) is now (?<state>\w+)\.?(?:\s+RTT: (?<rtt>[\d.]+) msec)?", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex ContactRegex();

    private static bool Registration(string message, LogEvent e)
    {
        if (AddedRegex().Match(message) is { Success: true } added)
        {
            Contact(e, added.Groups["aor"].Value, added.Groups["contact"].Value, "registered", "success");
            e.Fields["asterisk.expires"] = added.Groups["expires"].Value;
            return true;
        }
        if (RemovedRegex().Match(message) is { Success: true } removed)
        {
            Contact(e, removed.Groups["aor"].Value, removed.Groups["contact"].Value, "unregistered", "success");
            if (removed.Groups["reason"].Success)
            {
                e.Fields["asterisk.reason"] = removed.Groups["reason"].Value.TrimEnd('.');
            }
            return true;
        }
        if (EndpointRegex().Match(message) is { Success: true } endpoint)
        {
            var state = endpoint.Groups["state"].Value.ToLowerInvariant();
            e.EventDataset = RegistrationDataset;
            e.EventAction = $"endpoint-{state}";
            e.EventOutcome = state == "reachable" ? "success" : state == "unreachable" ? "failure" : "unknown";
            e.UserName = endpoint.Groups["endpoint"].Value;
            return true;
        }
        if (ContactRegex().Match(message) is { Success: true } contact)
        {
            var state = contact.Groups["state"].Value.ToLowerInvariant();
            Contact(e, contact.Groups["aor"].Value, contact.Groups["contact"].Value, $"contact-{state}",
                state == "reachable" ? "success" : state == "unreachable" ? "failure" : "unknown");
            if (contact.Groups["rtt"].Success)
            {
                e.Fields["asterisk.rtt_ms"] = contact.Groups["rtt"].Value;
            }
            return true;
        }
        return false;
    }

    private static void Contact(LogEvent e, string aor, string contact, string action, string outcome)
    {
        e.EventDataset = RegistrationDataset;
        e.EventAction = action;
        e.EventOutcome = outcome;
        e.UserName = aor;
        e.Fields["asterisk.contact"] = contact;
        // sip:114@216.160.83.56:9505;x-ast-orig-host=10.10.3.209:5060 → where the phone registered from.
        var at = contact.IndexOf('@', StringComparison.Ordinal);
        var hostPart = (at >= 0 ? contact[(at + 1)..] : contact.StartsWith("sip:", StringComparison.OrdinalIgnoreCase) ? contact[4..] : contact).Split(';')[0];
        if (HostPort(hostPart) is { } addr)
        {
            e.SourceIp = addr.Ip;
            e.SourcePort = addr.Port;
        }
        var origin = contact.IndexOf("x-ast-orig-host=", StringComparison.Ordinal);
        if (origin >= 0 && HostPort(contact[(origin + 16)..].Split(';')[0]) is { } inside)
        {
            e.Fields["asterisk.contact_private_ip"] = inside.Ip; // the phone's own LAN address behind NAT
        }
    }

    // ---- SIP packets (pjsip set logger on) ---------------------------------------------------

    [GeneratedRegex(@"^<--- (?<dir>Transmitting|Received) SIP (?<kind>request|response) \((?<bytes>\d+) bytes\) (?:to|from) (?<transport>\w+):(?<addr>\S+) --->", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex PacketRegex();

    private static bool SipPacket(string message, LogEvent e)
    {
        var newline = message.IndexOf('\n', StringComparison.Ordinal);
        var first = newline < 0 ? message : message[..newline].TrimEnd('\r');
        var m = PacketRegex().Match(first);
        if (!m.Success)
        {
            return false;
        }
        var inbound = m.Groups["dir"].Value == "Received";
        var transport = m.Groups["transport"].Value.ToLowerInvariant();
        e.EventDataset = SipDataset;
        e.NetworkProtocol = "sip";
        e.NetworkTransport = transport;
        e.Fields["network.direction"] = inbound ? "inbound" : "outbound";
        e.Fields["sip.bytes"] = m.Groups["bytes"].Value;
        var remote = HostPort(m.Groups["addr"].Value);
        if (remote is { } r)
        {
            if (inbound)
            {
                e.SourceIp = r.Ip;
                e.SourcePort = r.Port;
            }
            else
            {
                e.DestinationIp = r.Ip;
                e.DestinationPort = r.Port;
            }
        }

        var lines = newline < 0 ? [] : message[(newline + 1)..].Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        var startLine = lines.FirstOrDefault(l => l.Length > 0) ?? string.Empty;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var started = false;
        foreach (var line in lines)
        {
            if (!started)
            {
                started = line.Length > 0;
                continue;
            }
            if (line.Length == 0)
            {
                break; // the body follows
            }
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0)
            {
                var name = CompactHeader(line[..colon].Trim());
                headers.TryAdd(name, line[(colon + 1)..].Trim());
            }
        }

        var cseq = headers.GetValueOrDefault("CSeq");
        var cseqMethod = cseq?.Split(' ', StringSplitOptions.RemoveEmptyEntries) is [_, var cm, ..] ? cm : null;
        string summary;
        if (startLine.StartsWith("SIP/2.0 ", StringComparison.Ordinal))
        {
            var parts = startLine.Split(' ', 3);
            var code = parts.Length > 1 && int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var c) ? c : 0;
            e.EventAction = "response";
            e.EventOutcome = code switch { >= 200 and < 300 => "success", 401 or 407 => "unknown", >= 300 => "failure", _ => "unknown" };
            e.LogLevel = code >= 400 && code is not (401 or 407) ? "warning" : e.LogLevel;
            if (code > 0)
            {
                e.Fields["sip.status_code"] = code.ToString(CultureInfo.InvariantCulture);
            }
            if (parts.Length > 2)
            {
                e.Fields["sip.reason"] = parts[2];
            }
            if (cseqMethod is not null)
            {
                e.Fields["sip.method"] = cseqMethod;
            }
            summary = $"{startLine[8..]}{(cseqMethod is null ? "" : $" ({cseqMethod})")}";
        }
        else
        {
            var method = startLine.Split(' ')[0];
            if (method.Length > 0 && method.All(char.IsAsciiLetterUpper))
            {
                e.EventAction = method.ToLowerInvariant();
                e.Fields["sip.method"] = method;
                var uri = startLine.Split(' ') is [_, var u, ..] ? u : null;
                if (uri is not null)
                {
                    e.Fields["sip.request_uri"] = uri;
                }
            }
            summary = startLine.EndsWith(" SIP/2.0", StringComparison.Ordinal) ? startLine[..^8] : startLine;
        }

        if (headers.GetValueOrDefault("Call-ID") is { Length: > 0 } callId)
        {
            e.Fields["sip.call_id"] = callId;
        }
        if (cseq is not null)
        {
            e.Fields["sip.cseq"] = cseq;
        }
        if (headers.GetValueOrDefault("From") is { } from)
        {
            Party(e, "from", from);
        }
        if (headers.GetValueOrDefault("To") is { } to)
        {
            Party(e, "to", to);
        }
        if (headers.GetValueOrDefault("Contact") is { Length: > 0 } contactHeader)
        {
            e.Fields["sip.contact"] = contactHeader;
        }
        // The phone (or trunk) model: User-Agent on requests, Server on responses. Ours on what Asterisk sends.
        if ((headers.GetValueOrDefault("User-Agent") ?? headers.GetValueOrDefault("Server")) is { Length: > 0 } agent)
        {
            e.Fields["user_agent.original"] = agent;
        }
        if (headers.GetValueOrDefault("Via") is { Length: > 0 } via && inbound)
        {
            e.Fields["sip.via"] = via;
        }
        e.UserName = e.Fields.GetValueOrDefault("sip.from.user") ?? string.Empty;
        var peer = remote is { } p ? $"{p.Ip}:{p.Port}" : m.Groups["addr"].Value;
        e.Message = inbound ? $"Received {summary} from {peer}" : $"Sent {summary} to {peer}";
        return true;
    }

    /// <summary>SIP compact header forms (RFC 3261 §7.3.3).</summary>
    private static string CompactHeader(string name) => name.ToLowerInvariant() switch
    {
        "i" => "Call-ID",
        "f" => "From",
        "t" => "To",
        "m" => "Contact",
        "v" => "Via",
        "l" => "Content-Length",
        "c" => "Content-Type",
        _ => name,
    };

    private static void Party(LogEvent e, string role, string value)
    {
        if (UriUser(value) is { } user)
        {
            e.Fields[$"sip.{role}.user"] = user;
        }
        if (UriHost(value) is { } host)
        {
            e.Fields[$"sip.{role}.host"] = host;
        }
        if (Display(value) is { } display)
        {
            e.Fields[$"sip.{role}.display"] = display;
        }
    }

    // ---- Calls -------------------------------------------------------------------------------

    // Executing [114@from-internal:1] Dial("PJSIP/114-00000012", "PJSIP/115,,tr") in new stack
    [GeneratedRegex(@"^Executing \[(?<exten>[^@\]]*)@(?<context>[^:\]]+):(?<priority>\d+)\] (?<app>\w+)\(""(?<channel>[^""]*)"", ""(?<data>.*)""\) in new stack", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex ExecutingRegex();

    [GeneratedRegex(@"^(?:Called (?<called>\S+)|(?<ringing>\S+) is ringing|(?<answered>\S+) answered (?<caller>\S+))\s*$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex DialRegex();

    private static bool Call(string message, LogEvent e)
    {
        if (ExecutingRegex().Match(message) is { Success: true } x)
        {
            e.EventDataset = CallDataset;
            e.EventAction = "dialplan";
            e.Fields["asterisk.extension"] = x.Groups["exten"].Value;
            e.Fields["asterisk.context"] = x.Groups["context"].Value;
            e.Fields["asterisk.priority"] = x.Groups["priority"].Value;
            e.Fields["asterisk.application"] = x.Groups["app"].Value;
            e.Fields["asterisk.app_data"] = x.Groups["data"].Value;
            Channel(e, "asterisk.channel", x.Groups["channel"].Value, setUser: true);
            return true;
        }
        if (DialRegex().Match(message) is { Success: true } d)
        {
            e.EventDataset = CallDataset;
            if (d.Groups["called"].Success)
            {
                e.EventAction = "dial";
                e.Fields["asterisk.dialed"] = d.Groups["called"].Value;
            }
            else if (d.Groups["ringing"].Success)
            {
                e.EventAction = "ringing";
                Channel(e, "asterisk.channel", d.Groups["ringing"].Value, setUser: true);
            }
            else
            {
                e.EventAction = "answered";
                e.EventOutcome = "success";
                Channel(e, "asterisk.channel", d.Groups["answered"].Value, setUser: true);
                Channel(e, "asterisk.peer_channel", d.Groups["caller"].Value, setUser: false);
            }
            return true;
        }
        return false;
    }

    /// <summary><c>PJSIP/114-00000012</c> → channel, and endpoint <c>114</c> as the user.</summary>
    private static void Channel(LogEvent e, string field, string channel, bool setUser)
    {
        e.Fields[field] = channel;
        var slash = channel.IndexOf('/', StringComparison.Ordinal);
        var dash = channel.LastIndexOf('-');
        if (slash > 0 && dash > slash + 1)
        {
            var endpoint = channel[(slash + 1)..dash];
            e.Fields[field + "_endpoint"] = endpoint;
            if (setUser && e.UserName.Length == 0)
            {
                e.UserName = endpoint;
            }
        }
    }

    // ---- Helpers -----------------------------------------------------------------------------

    /// <summary><c>"114" &lt;sip:114@host&gt;;tag=x</c> → <c>114</c>.</summary>
    private static string? UriUser(string value)
    {
        var sip = value.IndexOf("sip:", StringComparison.OrdinalIgnoreCase);
        if (sip < 0)
        {
            sip = value.IndexOf("sips:", StringComparison.OrdinalIgnoreCase);
            if (sip < 0)
            {
                return null;
            }
            sip++;
        }
        var start = sip + 4;
        var at = value.IndexOf('@', start);
        var end = value.IndexOfAny(['>', ';', ' '], start);
        if (at < 0 || (end >= 0 && at > end))
        {
            return null;
        }
        var user = value[start..at];
        return user.Length == 0 ? null : Uri.UnescapeDataString(user);
    }

    private static string? UriHost(string value)
    {
        var sip = value.IndexOf("sip:", StringComparison.OrdinalIgnoreCase);
        if (sip < 0)
        {
            return null;
        }
        var start = sip + 4;
        var stop = value.IndexOfAny(['>', ';', ' '], start);
        var at = value.IndexOf('@', start);
        if (at >= 0 && (stop < 0 || at < stop))
        {
            start = at + 1;
        }
        var end = value.IndexOfAny(['>', ';', ' ', ':'], start);
        var host = end < 0 ? value[start..] : value[start..end];
        return host.Length == 0 ? null : host;
    }

    private static string? Display(string value)
    {
        var lt = value.IndexOf('<', StringComparison.Ordinal);
        if (lt <= 0)
        {
            return null;
        }
        var display = value[..lt].Trim().Trim('"').Trim();
        return display.Length == 0 ? null : display;
    }

    /// <summary><c>1.2.3.4:5060</c>, <c>[2001:db8::1]:5060</c> or a bare address.</summary>
    private static (string Ip, ushort Port)? HostPort(string value)
    {
        value = value.Trim();
        string host;
        string? port = null;
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
            {
                return null;
            }
            host = value[1..close];
            if (close + 1 < value.Length && value[close + 1] == ':')
            {
                port = value[(close + 2)..];
            }
        }
        else if (value.Count(c => c == ':') == 1)
        {
            var colon = value.IndexOf(':', StringComparison.Ordinal);
            host = value[..colon];
            port = value[(colon + 1)..];
        }
        else
        {
            host = value;
        }
        if (!IPAddress.TryParse(host, out var ip))
        {
            return null;
        }
        ushort.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var p);
        return (ip.ToString(), p);
    }

    /// <summary><c>InvalidPassword</c> → <c>invalid-password</c>.</summary>
    private static string Kebab(string name) => Separate(name, '-');

    private static string Snake(string name) => Separate(name, '_');

    private static string Separate(string name, char separator)
    {
        var sb = new StringBuilder(name.Length + 8);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c) && i > 0 && (char.IsLower(name[i - 1]) || (i + 1 < name.Length && char.IsLower(name[i + 1]))))
            {
                sb.Append(separator);
            }
            sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }
}
