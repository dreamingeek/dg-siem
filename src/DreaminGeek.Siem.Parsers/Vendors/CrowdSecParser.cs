using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// CrowdSec's logs (logrus <c>time="…" level=info msg="…" key=value</c>), e.g. from the container via Docker's
/// syslog log driver with <c>tag: crowdsec</c>.
/// <list type="bullet">
/// <item><c>crowdsec.decision</c>: a decision the local API recorded, e.g.
/// <c>(machine/crowdsec) crowdsecurity/http-probing by ip 1.2.3.4 (US/7018) : 4h ban on Ip 1.2.3.4</c>
/// → <c>event.action=ban</c>, <c>source.ip</c>, <c>rule.name</c> (the scenario), duration, country and ASN.</item>
/// <item><c>crowdsec.alert</c>: a scenario that triggered, e.g.
/// <c>Ip 1.2.3.4 performed 'crowdsecurity/http-probing' (11 events over 2.1s) at …</c>.</item>
/// <item><c>crowdsec.appsec</c>: WAF (AppSec) notices such as allowlisted clients.</item>
/// <item><c>crowdsec.lapi</c>: the local API's access log, mostly bouncers polling every few seconds; split out so
/// a drop rule can discard it.</item>
/// <item><c>crowdsec.log</c>: everything else.</item>
/// </list>
/// </summary>
public sealed partial class CrowdSecParser : IEventParser
{
    public const string Module = "crowdsec";

    public string Dataset => "crowdsec";
    public int Priority => 95;

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var m = envelope.Message;
        return m.Contains("msg=", StringComparison.Ordinal) && m.Contains("crowdsec", StringComparison.OrdinalIgnoreCase);
    }

    public bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        logEvent = null;
        var hasHeader = SyslogParser.TryParseHeader(envelope.Message, envelope.ReceivedAt, out var header);
        var body = hasHeader ? header.Message : envelope.Message;
        var start = body.IndexOf("time=", StringComparison.Ordinal);
        if (start < 0)
        {
            start = body.IndexOf("level=", StringComparison.Ordinal);
        }
        if (start < 0)
        {
            return false;
        }

        var kv = Logfmt(body.AsSpan(start));
        if (!kv.TryGetValue("msg", out var msg) || !kv.TryGetValue("level", out var level))
        {
            return false;
        }
        var fromCrowdSec = (hasHeader && header.AppName.Contains("crowdsec", StringComparison.OrdinalIgnoreCase))
            || (kv.TryGetValue("module", out var mod) && mod is "lapi" or "db" or "apic" or "papi" or "cti")
            || msg.Contains("crowdsec", StringComparison.OrdinalIgnoreCase);
        if (!fromCrowdSec)
        {
            return false;
        }

        var e = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = kv.TryGetValue("time", out var time) &&
                DateTimeOffset.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
                ? t : hasHeader ? header.Timestamp : envelope.ReceivedAt,
            HostName = hasHeader ? header.Hostname : string.Empty,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventModule = Module,
            EventDataset = "crowdsec.log",
            LogLevel = Level(level),
            Message = msg,
            Raw = envelope.Message,
        };
        var f = e.Fields;
        f["observer.vendor"] = "CrowdSec";
        f["observer.product"] = "CrowdSec";
        if (hasHeader && header.AppName.Length > 0)
        {
            f["process.name"] = header.AppName;
        }
        if (kv.TryGetValue("module", out var module))
        {
            f["crowdsec.module"] = module;
        }

        if (Decision().Match(msg) is { Success: true } d)
        {
            MapDecision(d, e);
        }
        else if (AlertOnly().Match(msg) is { Success: true } a)
        {
            e.EventDataset = "crowdsec.alert";
            e.EventAction = "alert";
            SetSource(e, a.Groups["scope"].Value, a.Groups["value"].Value, a.Groups["geo"].Value);
            f["rule.name"] = a.Groups["scenario"].Value;
            f["crowdsec.origin"] = a.Groups["origin"].Value;
            Alert(e, "warning");
        }
        else if (Overflow().Match(msg) is { Success: true } o)
        {
            e.EventDataset = "crowdsec.alert";
            e.EventAction = "scenario_triggered";
            SetSource(e, o.Groups["scope"].Value, o.Groups["value"].Value, string.Empty);
            f["rule.name"] = o.Groups["scenario"].Value;
            f["crowdsec.event_count"] = o.Groups["count"].Value;
            f["crowdsec.over"] = o.Groups["over"].Value;
            Alert(e, "notice");
        }
        else if (LapiAccess().Match(msg) is { Success: true } l)
        {
            e.EventDataset = "crowdsec.lapi";
            e.SourceIp = l.Groups["ip"].Value;
            e.NetworkProtocol = "http";
            f["http.request.method"] = l.Groups["method"].Value;
            f["url.original"] = l.Groups["path"].Value;
            var path = l.Groups["path"].Value;
            var q = path.IndexOf('?', StringComparison.Ordinal);
            f["url.path"] = q < 0 ? path : path[..q];
            f["http.response.status_code"] = l.Groups["status"].Value;
            if (l.Groups["ua"].Success && l.Groups["ua"].Value.Length > 0)
            {
                f["user_agent.original"] = l.Groups["ua"].Value;
            }
            e.EventOutcome = int.Parse(l.Groups["status"].Value, CultureInfo.InvariantCulture) < 400 ? "success" : "failure";
        }
        else if (Allowlisted().Match(msg) is { Success: true } w)
        {
            e.EventDataset = "crowdsec.appsec";
            e.EventAction = "allowlisted";
            e.SourceIp = w.Groups["ip"].Value;
            f["crowdsec.allowlist"] = w.Groups["list"].Value.Trim();
        }
        else if (module is not null && module.StartsWith("acquisition.appsec", StringComparison.Ordinal))
        {
            e.EventDataset = "crowdsec.appsec";
        }

        logEvent = e;
        return true;
    }

    private static void MapDecision(Match d, LogEvent e)
    {
        var f = e.Fields;
        e.EventDataset = "crowdsec.decision";
        e.EventAction = d.Groups["type"].Value; // ban, captcha, ...
        SetSource(e, d.Groups["scope"].Value, d.Groups["value"].Value, d.Groups["geo"].Value);
        f["rule.name"] = d.Groups["scenario"].Value;
        f["crowdsec.origin"] = d.Groups["origin"].Value;
        f["crowdsec.decision.duration"] = d.Groups["duration"].Value;
        f["crowdsec.decision.scope"] = d.Groups["dscope"].Value;
        f["crowdsec.decision.value"] = d.Groups["dvalue"].Value;
        if (d.Groups["sim"].Success)
        {
            f["crowdsec.simulated"] = "true";
        }
        Alert(e, "warning");
        var who = e.SourceIp.Length > 0 ? e.SourceIp : d.Groups["dvalue"].Value;
        e.Message = $"{d.Groups["duration"].Value} {e.EventAction} on {who} for {d.Groups["scenario"].Value}"
            + (f.TryGetValue("source.geo.country_iso_code", out var country) ? $" ({country})" : string.Empty);
    }

    private static void Alert(LogEvent e, string level)
    {
        e.LogLevel = level;
        e.EventOutcome = "success";
        e.Fields["event.kind"] = "alert";
        e.Fields["event.category"] = "intrusion_detection";
    }

    /// <summary><c>ip 1.2.3.4</c> / <c>range 1.2.3.0/24</c> plus <c>US/7018</c> (country / ASN).</summary>
    private static void SetSource(LogEvent e, string scope, string value, string geo)
    {
        if (scope.Equals("ip", StringComparison.OrdinalIgnoreCase))
        {
            e.SourceIp = value;
        }
        else
        {
            e.Fields["crowdsec.source.scope"] = scope.ToLowerInvariant();
            e.Fields["crowdsec.source.value"] = value;
        }
        if (geo.Length > 0)
        {
            var slash = geo.IndexOf('/', StringComparison.Ordinal);
            var country = slash < 0 ? geo : geo[..slash];
            if (country.Length > 0)
            {
                e.Fields["source.geo.country_iso_code"] = country;
            }
            if (slash >= 0 && slash < geo.Length - 1)
            {
                e.Fields["source.as.number"] = geo[(slash + 1)..];
            }
        }
    }

    private static string Level(string level) => level.ToLowerInvariant() switch
    {
        "debug" or "trace" => "debug",
        "warning" or "warn" => "warning",
        "error" => "error",
        "fatal" or "panic" => "critical",
        _ => "informational",
    };

    /// <summary>logrus text format: <c>key=value</c> pairs, values optionally double-quoted with backslash escapes.</summary>
    public static Dictionary<string, string> Logfmt(ReadOnlySpan<char> text)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var i = 0;
        while (i < text.Length)
        {
            while (i < text.Length && text[i] == ' ')
            {
                i++;
            }
            var keyStart = i;
            while (i < text.Length && text[i] != '=' && text[i] != ' ')
            {
                i++;
            }
            if (i >= text.Length || text[i] != '=')
            {
                // A bare word; skip it.
                continue;
            }
            var key = text[keyStart..i].ToString();
            i++;
            string value;
            if (i < text.Length && text[i] == '"')
            {
                var sb = new StringBuilder();
                i++;
                while (i < text.Length && text[i] != '"')
                {
                    if (text[i] == '\\' && i + 1 < text.Length)
                    {
                        i++;
                        sb.Append(text[i] switch { 'n' => '\n', 't' => '\t', _ => text[i] });
                    }
                    else
                    {
                        sb.Append(text[i]);
                    }
                    i++;
                }
                i++;
                value = sb.ToString();
            }
            else
            {
                var valueStart = i;
                while (i < text.Length && text[i] != ' ')
                {
                    i++;
                }
                value = text[valueStart..i].ToString();
            }
            if (key.Length > 0)
            {
                result[key] = value;
            }
        }
        return result;
    }

    // "(machine/crowdsec) crowdsecurity/http-probing by ip 1.2.3.4 (US/7018) : 4h ban on Ip 1.2.3.4"
    // (reason may end "for 1/2 decisions"; the decision may be prefixed "(simulated alert)" / "(simulated decision)")
    [GeneratedRegex(@"^\((?<origin>[^)]*)\) (?<scenario>.+?)(?: for \d+/\d+ decisions)? by (?<scope>\w+) (?<value>\S+)(?: \((?<geo>[^)]*)\))? : (?<sim>\(simulated (?:alert|decision)\))?(?<duration>\S+) (?<type>\S+) on (?<dscope>\S+) (?<dvalue>\S+)$", RegexOptions.CultureInvariant, 200)]
    private static partial Regex Decision();

    // "(machine/crowdsec) alert : crowdsecurity/x by ip 1.2.3.4 (US/7018)" (an alert with no decision)
    [GeneratedRegex(@"^\((?<origin>[^)]*)\) alert : (?<scenario>.+?) by (?<scope>\w+) (?<value>\S+)(?: \((?<geo>[^)]*)\))?$", RegexOptions.CultureInvariant, 200)]
    private static partial Regex AlertOnly();

    // "Ip 1.2.3.4 performed 'crowdsecurity/http-probing' (11 events over 2.1s) at 2026-11-12 05:35:00 +0000 UTC"
    [GeneratedRegex(@"^(?<scope>\w+) (?<value>\S+) performed '(?<scenario>[^']+)' \((?<count>\d+) events over (?<over>[^)]+)\)", RegexOptions.CultureInvariant, 200)]
    private static partial Regex Overflow();

    // "172.18.0.4 - [Thu, 12 Nov 2026 05:33:51 UTC] "GET /v1/decisions/stream?startup=false HTTP/1.1 200 6.17ms "Crowdsec-Bouncer-Traefik-Plugin/v1.8.1" ""
    [GeneratedRegex(@"^(?<ip>\S+) - \[[^\]]*\] ""(?<method>[A-Z]+) (?<path>\S+) HTTP/[\d.]+ (?<status>\d{3}) \S+ ""(?<ua>[^""]*)""", RegexOptions.CultureInvariant, 200)]
    private static partial Regex LapiAccess();

    // "216.160.83.56 is allowlisted by 216.160.83.56 from dg-trusted, skipping WAF processing"
    [GeneratedRegex(@"^(?<ip>\S+) is allowlisted by \S+(?: from (?<list>[^,]+))?", RegexOptions.CultureInvariant, 200)]
    private static partial Regex Allowlisted();
}
