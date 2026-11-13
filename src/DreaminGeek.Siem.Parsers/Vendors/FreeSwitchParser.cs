using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// FreeSWITCH (FusionPBX, FS PBX) <c>freeswitch.log</c>, tailed by the agent or forwarded by rsyslog's imfile:
/// <c>[call-uuid ]2026-11-10 18:53:39.395484 96.73% [NOTICE] file.c:123 message</c> (the percentage is idle CPU).
/// <list type="bullet">
/// <item><c>freeswitch.security</c>: <c>SIP auth failure</c>, <c>Can't find user</c> (scanners guessing
/// extensions) and ACL rejections, which is what FusionPBX's fail2ban watches.</item>
/// <item><c>freeswitch.registration</c>: phone registrations and auth challenges; trunk (gateway) pings and
/// failed registrations.</item>
/// <item><c>freeswitch.call</c>: new channels, answers and hangups with the hangup cause, tied together by the
/// call's UUID.</item>
/// <item><c>freeswitch.log</c>: everything else (including the per-call DEBUG state-machine chatter, which a
/// drop rule on <c>log.level=debug</c> can discard).</item>
/// </list>
/// </summary>
public sealed partial class FreeSwitchParser : IEventParser
{
    public const string Module = "freeswitch";
    public const string LogDataset = "freeswitch.log";
    public const string SecurityDataset = "freeswitch.security";
    public const string RegistrationDataset = "freeswitch.registration";
    public const string CallDataset = "freeswitch.call";

    public string Dataset => LogDataset;
    public int Priority => 80;

    [GeneratedRegex(
        @"^(?:(?<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) )?" +
        @"(?<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) (?:(?<cpu>\d+(?:\.\d+)?)% )?" +
        @"\[(?<level>DEBUG|INFO|NOTICE|WARNING|ERR|ERROR|CRIT|ALERT|CONSOLE)\] (?<file>[\w./+-]+\.(?:c|cpp|h)):(?<line>\d+) (?<msg>.*)$",
        RegexOptions.Singleline | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex LineRegex();

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var m = envelope.Message.AsSpan(0, Math.Min(envelope.Message.Length, 200));
        return m.Contains("% [", StringComparison.Ordinal) || (m.Contains("] ", StringComparison.Ordinal) && m.Contains(".c:", StringComparison.Ordinal));
    }

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

        var message = m.Groups["msg"].Value.TrimEnd();
        var e = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = LocalTime.Resolve(m.Groups["ts"].Value, hasHeader ? header : null, envelope.ReceivedAt, out var zone),
            HostName = hasHeader ? header.Hostname : string.Empty,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventDataset = LogDataset,
            EventModule = Module,
            LogLevel = m.Groups["level"].Value switch
            {
                "ERR" or "ERROR" => "error",
                "CRIT" => "critical",
                "ALERT" => "alert",
                "WARNING" => "warning",
                "NOTICE" => "notice",
                "DEBUG" => "debug",
                _ => "informational",
            },
            Message = message,
            Raw = envelope.Message,
        };
        e.Fields["log.origin.file.name"] = m.Groups["file"].Value;
        e.Fields["log.origin.file.line"] = m.Groups["line"].Value;
        if (m.Groups["uuid"].Success)
        {
            e.Fields["freeswitch.uuid"] = m.Groups["uuid"].Value;
        }
        if (m.Groups["cpu"].Success)
        {
            e.Fields["freeswitch.cpu_idle_pct"] = m.Groups["cpu"].Value;
        }
        if (zone is { } offset)
        {
            e.Fields["event.timezone"] = SyslogParser.FormatOffset(offset);
        }

        try
        {
            var first = message.Split('\n', 2)[0].TrimEnd('\r');
            var recognised = Security(first, e) || Registration(message, first, e) || Call(first, e);
            if (!recognised)
            {
                Channel(first, e);
                if (e.LogLevel is "warning" or "error" or "critical" or "alert")
                {
                    e.EventOutcome = "failure";
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // Keep the generic event.
        }
        logEvent = e;
        return true;
    }

    // ---- Security ----------------------------------------------------------------------------

    // SIP auth failure (REGISTER) on sofia profile 'internal' for [100@office.pbx.example.com] from ip 203.0.113.50
    [GeneratedRegex(@"^SIP auth (?<kind>failure|challenge) \((?<method>[A-Z]+)\) on sofia profile '(?<profile>[^']+)' for \[(?<user>[^@\]]*)@?(?<domain>[^\]]*)\] from ip (?<ip>\S+)", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex AuthRegex();

    // Can't find user [1001@198.51.100.243] from 203.0.113.95
    [GeneratedRegex(@"^Can't find user \[(?<user>[^@\]]*)@?(?<domain>[^\]]*)\] from (?<ip>\S+)", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex UnknownUserRegex();

    // IP 203.0.113.50 Rejected by acl "domains"[. Falling back to Digest auth.]
    [GeneratedRegex(@"^IP (?<ip>\S+) Rejected by (?<which>(?:register |proxy )?acl) ""(?<acl>[^""]*)""(?<fallback>\. Falling back to Digest auth)?", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex AclRegex();

    private static bool Security(string first, LogEvent e)
    {
        if (AuthRegex().Match(first) is { Success: true } auth)
        {
            var failure = auth.Groups["kind"].Value == "failure";
            e.EventDataset = failure ? SecurityDataset : RegistrationDataset;
            e.EventAction = failure ? "auth-failed" : "auth-challenge";
            e.EventOutcome = failure ? "failure" : "unknown";
            e.NetworkProtocol = "sip";
            e.UserName = auth.Groups["user"].Value;
            e.Fields["sip.method"] = auth.Groups["method"].Value;
            e.Fields["freeswitch.profile"] = auth.Groups["profile"].Value;
            Domain(e, auth.Groups["domain"].Value);
            SourceIp(e, auth.Groups["ip"].Value);
            Category(e);
            return true;
        }
        if (UnknownUserRegex().Match(first) is { Success: true } unknown)
        {
            e.EventDataset = SecurityDataset;
            e.EventAction = "unknown-account";
            e.EventOutcome = "failure";
            e.NetworkProtocol = "sip";
            e.UserName = unknown.Groups["user"].Value;
            Domain(e, unknown.Groups["domain"].Value);
            SourceIp(e, unknown.Groups["ip"].Value);
            e.Message = first; // FreeSWITCH adds two lines of setup advice
            Category(e);
            return true;
        }
        if (AclRegex().Match(first) is { Success: true } acl)
        {
            var fallback = acl.Groups["fallback"].Success;
            e.EventDataset = SecurityDataset;
            e.EventAction = fallback ? "acl-digest-fallback" : "acl-denied";
            e.EventOutcome = fallback ? "unknown" : "failure";
            e.NetworkProtocol = "sip";
            e.Fields["freeswitch.acl"] = acl.Groups["acl"].Value;
            e.Fields["freeswitch.acl_type"] = acl.Groups["which"].Value.Replace(' ', '_');
            SourceIp(e, acl.Groups["ip"].Value);
            Category(e);
            return true;
        }
        return false;
    }

    private static void Category(LogEvent e)
    {
        e.Fields["event.kind"] = "event";
        e.Fields["event.category"] = "authentication";
    }

    // ---- Registrations and gateways ----------------------------------------------------------

    // Register:\nFrom:    [100@office.pbx.example.com]\nContact: ["Front Desk" <sip:100@10.1.1.160:7057;...;fs_path=...>]\nExpires: [120]
    [GeneratedRegex(@"^(?<what>Register|Unregister|Delete registration|Expired registration):?\s*\nFrom:\s*\[(?<user>[^@\]]*)@?(?<domain>[^\]]*)\]\s*\nContact:\s*\[(?<contact>[^\n]*)\](?:\s*\nExpires:\s*\[(?<expires>\d+)\])?", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex RegisterRegex();

    // Ping failed voipms with code 503 - count 1/2/2, state DOWN   /   Ping succeeded voipms with code 200 - count 1/1/2, state UP
    [GeneratedRegex(@"^Ping (?<result>failed|succeeded) (?<gw>\S+) with code (?<code>\d+) - count [\d/-]+, state (?<state>\w+)", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex PingRegex();

    // voipms Failed Registration with status 403 [403]. failure #2   /   voipms Failed Registration [403], setting retry to 30 seconds.
    [GeneratedRegex(@"^(?<gw>\S+) Failed Registration(?: with status (?<status>[^\s\[]+))?(?: ?\[(?<code>\d+)\])?", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex GatewayFailedRegex();

    private static bool Registration(string message, string first, LogEvent e)
    {
        if (RegisterRegex().Match(message) is { Success: true } reg)
        {
            var what = reg.Groups["what"].Value;
            e.EventDataset = RegistrationDataset;
            e.EventAction = what == "Register" ? "registered" : what.StartsWith("Expired", StringComparison.Ordinal) ? "expired" : "unregistered";
            e.EventOutcome = "success";
            e.NetworkProtocol = "sip";
            e.UserName = reg.Groups["user"].Value;
            Domain(e, reg.Groups["domain"].Value);
            var contact = reg.Groups["contact"].Value;
            e.Fields["freeswitch.contact"] = contact;
            if (reg.Groups["expires"].Success)
            {
                e.Fields["freeswitch.expires"] = reg.Groups["expires"].Value;
            }
            Contact(e, contact);
            e.Message = $"{(e.EventAction == "registered" ? "Registered" : what)} {e.UserName}@{reg.Groups["domain"].Value}{(e.SourceIp.Length > 0 ? $" from {e.SourceIp}" : "")}";
            return true;
        }
        if (PingRegex().Match(first) is { Success: true } ping)
        {
            var ok = ping.Groups["result"].Value == "succeeded";
            e.EventDataset = RegistrationDataset;
            e.EventAction = ok ? "gateway-ping-ok" : "gateway-ping-failed";
            e.EventOutcome = ok ? "success" : "failure";
            e.Fields["freeswitch.gateway"] = ping.Groups["gw"].Value;
            e.Fields["freeswitch.gateway_state"] = ping.Groups["state"].Value.ToLowerInvariant();
            e.Fields["sip.status_code"] = ping.Groups["code"].Value;
            return true;
        }
        if (GatewayFailedRegex().Match(first) is { Success: true } gw)
        {
            e.EventDataset = RegistrationDataset;
            e.EventAction = "gateway-registration-failed";
            e.EventOutcome = "failure";
            e.Fields["freeswitch.gateway"] = gw.Groups["gw"].Value;
            if (gw.Groups["code"].Success)
            {
                e.Fields["sip.status_code"] = gw.Groups["code"].Value;
            }
            return true;
        }
        return false;
    }

    /// <summary>
    /// The phone's public address: <c>fs_path=sip%3A100%40198.51.100.240%3A7057</c> or <c>received=</c> when it's
    /// behind NAT, otherwise the contact's own host. The contact host is its LAN address in that case.
    /// </summary>
    private static void Contact(LogEvent e, string contact)
    {
        var decoded = Uri.UnescapeDataString(contact);
        var at = decoded.IndexOf('@', StringComparison.Ordinal);
        var lanHost = at < 0 ? null : HostOf(decoded[(at + 1)..]);
        string? publicHost = null;
        foreach (var marker in (string[])["fs_path=<sip:", "fs_path=sip:", "received="])
        {
            var i = decoded.IndexOf(marker, StringComparison.Ordinal);
            if (i < 0)
            {
                continue;
            }
            var rest = decoded[(i + marker.Length)..];
            var stop = rest.IndexOfAny([';', '>', ' ', '"']);
            var target = stop < 0 ? rest : rest[..stop];          // 100@198.51.100.240:7057 or 198.51.100.240:7057
            publicHost = HostOf(target[(target.IndexOf('@', StringComparison.Ordinal) + 1)..]);
            if (publicHost is not null)
            {
                break;
            }
        }
        if (publicHost is not null)
        {
            SourceIp(e, publicHost);
            if (lanHost is not null && lanHost != publicHost)
            {
                e.Fields["freeswitch.contact_private_ip"] = lanHost;
            }
        }
        else if (lanHost is not null)
        {
            SourceIp(e, lanHost);
        }
    }

    /// <summary>The IP at the start of <c>198.51.100.240:7057;transport=tcp</c>, or null when it isn't an address.</summary>
    private static string? HostOf(string value)
    {
        var end = value.IndexOfAny([':', ';', '>', ' ', '"', ']']);
        var host = end < 0 ? value : value[..end];
        return IPAddress.TryParse(host, out _) ? host : null;
    }

    // ---- Calls -------------------------------------------------------------------------------

    [GeneratedRegex(@"^New Channel (?<channel>\S+) \[(?<uuid>[0-9a-f-]{36})\]", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex NewChannelRegex();

    [GeneratedRegex(@"^Channel \[(?<channel>[^\]]+)\] has been answered", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex AnsweredRegex();

    // Hangup sofia/internal/100@office.pbx.example.com [CS_EXECUTE] [NORMAL_CLEARING]
    [GeneratedRegex(@"^Hangup (?<channel>\S+) \[(?<state>CS_\w+)\] \[(?<cause>\w+)\]", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex HangupRegex();

    // Channel sofia/external/2125550100@203.0.113.29 hanging up, cause: NORMAL_CLEARING
    [GeneratedRegex(@"^Channel (?<channel>\S+) hanging up, cause: (?<cause>\w+)", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex HangingUpRegex();

    /// <summary>Hangup causes that mean the call worked or was simply not taken.</summary>
    private static readonly HashSet<string> NormalCauses = new(StringComparer.Ordinal)
    {
        "NORMAL_CLEARING", "ORIGINATOR_CANCEL", "USER_BUSY", "NO_ANSWER", "NO_USER_RESPONSE", "ATTENDED_TRANSFER",
        "BLIND_TRANSFER", "PICKED_OFF", "LOSE_RACE", "SUCCESS", "CALL_REJECTED", "NORMAL_UNSPECIFIED",
    };

    private static bool Call(string first, LogEvent e)
    {
        if (NewChannelRegex().Match(first) is { Success: true } created)
        {
            CallEvent(e, "new-channel", created.Groups["channel"].Value);
            e.Fields.TryAdd("freeswitch.uuid", created.Groups["uuid"].Value);
            return true;
        }
        if (AnsweredRegex().Match(first) is { Success: true } answered)
        {
            CallEvent(e, "answered", answered.Groups["channel"].Value);
            e.EventOutcome = "success";
            return true;
        }
        var hangup = HangupRegex().Match(first) is { Success: true } h ? h : HangingUpRegex().Match(first);
        if (hangup.Success)
        {
            var cause = hangup.Groups["cause"].Value;
            CallEvent(e, "hangup", hangup.Groups["channel"].Value);
            e.Fields["freeswitch.hangup_cause"] = cause;
            if (hangup.Groups["state"].Success)
            {
                e.Fields["freeswitch.channel_state"] = hangup.Groups["state"].Value;
            }
            e.EventOutcome = NormalCauses.Contains(cause) ? "success" : "failure";
            return true;
        }
        return false;
    }

    private static void CallEvent(LogEvent e, string action, string channel)
    {
        e.EventDataset = CallDataset;
        e.EventAction = action;
        e.NetworkProtocol = "sip";
        SetChannel(e, channel);
    }

    // (sofia/external/2125550100@203.0.113.29) or a bare sofia/internal/100@domain in state-machine lines.
    [GeneratedRegex(@"(?<channel>sofia/[\w.-]+/[^\s)\]]+)", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex ChannelRegex();

    private static void Channel(string first, LogEvent e)
    {
        if (ChannelRegex().Match(first) is { Success: true } c)
        {
            SetChannel(e, c.Groups["channel"].Value);
        }
    }

    /// <summary><c>sofia/internal/100@domain</c>: profile, the user or number, and the extension as user on the internal profile.</summary>
    private static void SetChannel(LogEvent e, string channel)
    {
        e.Fields["freeswitch.channel"] = channel;
        var parts = channel.Split('/', 3);
        if (parts.Length < 3)
        {
            return;
        }
        e.Fields["freeswitch.profile"] = parts[1];
        var at = parts[2].IndexOf('@', StringComparison.Ordinal);
        var who = at < 0 ? parts[2] : parts[2][..at];
        var host = at < 0 ? string.Empty : parts[2][(at + 1)..];
        e.Fields["freeswitch.channel_user"] = who;
        if (host.Length > 0)
        {
            e.Fields["freeswitch.channel_host"] = host;
        }
        // Internal-profile channels are extensions; external ones are trunk legs whose "user" is a phone number.
        if (parts[1] == "internal" && e.UserName.Length == 0)
        {
            e.UserName = who;
        }
    }

    // ---- Helpers -----------------------------------------------------------------------------

    private static void Domain(LogEvent e, string domain)
    {
        if (domain.Length > 0)
        {
            e.Fields["sip.domain"] = domain;
        }
    }

    private static void SourceIp(LogEvent e, string value)
    {
        if (IPAddress.TryParse(value.Trim('[', ']'), out var ip))
        {
            e.SourceIp = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
        }
    }
}

/// <summary>Turns a zone-less local timestamp inside a line into UTC (shared by the PBX parsers).</summary>
internal static class LocalTime
{
    /// <param name="text"><c>2026-11-12 10:31:16[.ffffff]</c> or <c>Nov 12 10:31:16</c>.</param>
    public static DateTimeOffset Resolve(string text, SyslogParser.SyslogHeader? header, DateTimeOffset receivedAt, out TimeSpan? zone)
    {
        zone = null;
        var reference = header?.Timestamp ?? receivedAt;
        if (string.IsNullOrEmpty(text))
        {
            zone = header?.TimeZoneOffset;
            return reference;
        }
        DateTime wall;
        if (char.IsAsciiDigit(text[0]))
        {
            if (!DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out wall))
            {
                return reference;
            }
        }
        else if (!DateTime.TryParseExact($"{reference.Year} {text}", ["yyyy MMM d HH:mm:ss", "yyyy MMM d HH:mm:ss.FFFFFF"],
                     CultureInfo.InvariantCulture, DateTimeStyles.AllowInnerWhite, out wall))
        {
            return reference;
        }

        // A BSD syslog header whose offset was worked out, or the agent's / rsyslog's RFC 5424 header with the
        // host's offset: the line was written in that zone.
        if (header?.TimeZoneOffset is { } known)
        {
            zone = known;
            return new DateTimeOffset(wall, known).ToUniversalTime();
        }
        var headerOffset = header?.Timestamp.Offset ?? TimeSpan.Zero;
        if (headerOffset != TimeSpan.Zero)
        {
            zone = headerOffset;
            return new DateTimeOffset(wall, headerOffset).ToUniversalTime();
        }
        (var utc, zone) = SyslogParser.ResolveLocalTime(new DateTimeOffset(wall, TimeSpan.Zero), reference.ToUniversalTime());
        return utc;
    }
}
