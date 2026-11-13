using System.Globalization;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers;

/// <summary>
/// Generic syslog parser for RFC 5424 and RFC 3164 (BSD) messages. This is the fallback
/// for any syslog source; vendor parsers (UniFi, SIP phones, ...) run before it and can
/// reuse <see cref="TryParseHeader"/> to split the header from the vendor payload.
/// </summary>
public sealed class SyslogParser : IEventParser
{
    private static readonly string[] Severities =
        ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"];

    public string Dataset => "syslog";
    public int Priority => 1000;

    public bool CanParse(RawEnvelope envelope) =>
        envelope.Message.Length > 2 && (envelope.Message[0] == '<' || StartsWithBsdTimestamp(envelope.Message));

    public bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent)
    {
        logEvent = null;
        if (!TryParseHeader(envelope.Message, envelope.ReceivedAt, out var header))
        {
            return false;
        }

        logEvent = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = header.Timestamp,
            HostName = header.Hostname,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventDataset = envelope.DatasetHint ?? Dataset,
            EventModule = "syslog",
            LogLevel = SeverityName(header.Severity),
            Message = header.Message,
            Raw = envelope.Message,
        };
        logEvent.Fields["log.syslog.facility.code"] = header.Facility.ToString(CultureInfo.InvariantCulture);
        logEvent.Fields["log.syslog.severity.code"] = header.Severity.ToString(CultureInfo.InvariantCulture);
        if (header.AppName.Length > 0)
        {
            logEvent.Fields["process.name"] = header.AppName;
        }
        if (header.ProcId.Length > 0)
        {
            logEvent.Fields["process.pid"] = header.ProcId;
        }
        if (header.TimeZoneOffset is { } offset)
        {
            logEvent.Fields["event.timezone"] = FormatOffset(offset);
        }
        return true;
    }

    /// <summary>Syslog severity code (0-7) → ECS <c>log.level</c> name.</summary>
    public static string SeverityName(int severity) => Severities[Math.Clamp(severity, 0, 7)];

    public readonly record struct SyslogHeader(
        int Facility, int Severity, DateTimeOffset Timestamp, string Hostname,
        string AppName, string ProcId, string Message)
    {
        /// <summary>Sender's UTC offset inferred for an RFC 3164 local-time timestamp, if any.</summary>
        public TimeSpan? TimeZoneOffset { get; init; }
    }

    /// <summary>ECS <c>event.timezone</c> for an inferred offset, e.g. <c>-06:00</c>.</summary>
    public static string FormatOffset(TimeSpan offset) =>
        (offset < TimeSpan.Zero ? "-" : "+") + offset.Duration().ToString(@"hh\:mm", CultureInfo.InvariantCulture);

    /// <summary>Parses the PRI and header of an RFC 5424 or RFC 3164 message.</summary>
    public static bool TryParseHeader(string line, DateTimeOffset receivedAt, out SyslogHeader header)
    {
        header = default;
        var span = line.AsSpan();
        int pri;
        string rest;
        if (span.Length >= 3 && span[0] == '<')
        {
            var close = span.IndexOf('>');
            if (close is < 2 or > 4 || !int.TryParse(span[1..close], NumberStyles.None, CultureInfo.InvariantCulture, out pri) || pri > 191)
            {
                return false;
            }
            rest = line[(close + 1)..];
        }
        else if (StartsWithBsdTimestamp(line))
        {
            // Some senders (UniFi OS's SIEM output, for one) omit the <PRI>. Assume user.notice.
            pri = 13;
            rest = line;
        }
        else
        {
            return false;
        }

        var facility = pri / 8;
        var severity = pri % 8;

        // RFC 5424: "<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
        if (rest.StartsWith("1 ", StringComparison.Ordinal))
        {
            var parts = rest.Split(' ', 7);
            if (parts.Length < 6)
            {
                return false;
            }

            var ts = parts[1] == "-" ? receivedAt
                : DateTimeOffset.TryParse(parts[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedTs) ? parsedTs : receivedAt;
            var msg = parts.Length == 7 ? StripStructuredData(parts[6]) : string.Empty;
            header = new SyslogHeader(facility, severity, ts, Nil(parts[2]), Nil(parts[3]), Nil(parts[4]), msg);
            return true;
        }

        // RFC 3164: "<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG" (timestamp has no year/zone).
        string hostname = string.Empty, app = string.Empty, procId = string.Empty, message = rest;
        var timestamp = receivedAt;
        TimeSpan? zone = null;
        if (rest.Length >= 16 && DateTime.TryParseExact(rest[..15].Replace("  ", " 0", StringComparison.Ordinal), "MMM dd HH:mm:ss",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var bsdTs))
        {
            var wallClock = new DateTimeOffset(receivedAt.Year, bsdTs.Month, bsdTs.Day, bsdTs.Hour, bsdTs.Minute, bsdTs.Second, TimeSpan.Zero);
            // Year rollover: a "Dec 31" line received on Jan 1 belongs to last year.
            if (wallClock > receivedAt.AddDays(1))
            {
                wallClock = wallClock.AddYears(-1);
            }
            (timestamp, zone) = ResolveLocalTime(wallClock, receivedAt);

            var afterTs = rest[16..];
            var space = afterTs.IndexOf(' ');
            if (space > 0)
            {
                hostname = afterTs[..space];
                message = afterTs[(space + 1)..];
                // Some senders (UniFi gateways) repeat the hostname: "HOST HOST tag: msg".
                if (message.StartsWith(hostname + " ", StringComparison.Ordinal))
                {
                    message = message[(hostname.Length + 1)..];
                }
            }
            else
            {
                message = afterTs;
            }
        }

        var colon = message.IndexOf(": ", StringComparison.Ordinal);
        if (colon > 0 && colon < 64 && !message[..colon].Contains(' ', StringComparison.Ordinal))
        {
            var tag = message[..colon];
            var bracket = tag.IndexOf('[');
            if (bracket > 0 && tag.EndsWith(']'))
            {
                app = tag[..bracket];
                procId = tag[(bracket + 1)..^1];
            }
            else
            {
                app = tag;
            }
            message = message[(colon + 2)..];
        }

        header = new SyslogHeader(facility, severity, timestamp, hostname, app, procId, message) { TimeZoneOffset = zone };
        return true;
    }

    /// <summary>
    /// RFC 3164 timestamps are the sender's wall clock with no zone. Most devices log in local time,
    /// so infer the zone from when the agent received the line: if the gap between wall clock and
    /// receive time is (within 2 minutes) a whole number of quarter-hours up to ±14h, that gap is the
    /// sender's UTC offset (zones are never less than an hour from UTC). Otherwise the clock is wrong
    /// rather than offset, and the wall clock is kept as UTC.
    /// </summary>
    public static (DateTimeOffset Utc, TimeSpan? Offset) ResolveLocalTime(DateTimeOffset wallClockAsUtc, DateTimeOffset receivedAt)
    {
        var gap = wallClockAsUtc - receivedAt;
        var quarterHours = Math.Round(gap.TotalMinutes / 15, MidpointRounding.AwayFromZero);
        var offset = TimeSpan.FromMinutes(quarterHours * 15);
        // Real zones are at least 1h from UTC (and quarter-hour aligned, e.g. +05:45); anything closer is clock drift.
        if (Math.Abs(offset.TotalHours) is < 1 or > 14 || (gap - offset).Duration() > TimeSpan.FromMinutes(2))
        {
            return (wallClockAsUtc, null);
        }
        return (wallClockAsUtc - offset, offset);
    }

    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    /// <summary>True for lines starting <c>"Mmm dd hh:mm:ss "</c> (an RFC 3164 timestamp with no PRI).</summary>
    internal static bool StartsWithBsdTimestamp(string line) =>
        line.Length >= 16 && line[3] == ' ' && line[6] == ' ' && line[9] == ':' && line[12] == ':' && line[15] == ' ' &&
        Array.IndexOf(Months, line[..3]) >= 0;

    private static string Nil(string value) => value == "-" ? string.Empty : value;

    private static string StripStructuredData(string value)
    {
        if (value.StartsWith("- ", StringComparison.Ordinal))
        {
            return value[2..];
        }
        if (value == "-")
        {
            return string.Empty;
        }
        if (!value.StartsWith('['))
        {
            return value;
        }

        // Skip one or more [SD-ELEMENT] blocks, honoring escaped \] inside values.
        var i = 0;
        while (i < value.Length && value[i] == '[')
        {
            i++;
            while (i < value.Length && value[i] != ']')
            {
                i += value[i] == '\\' ? 2 : 1;
            }
            i++;
        }
        return i < value.Length ? value[i..].TrimStart() : string.Empty;
    }
}
