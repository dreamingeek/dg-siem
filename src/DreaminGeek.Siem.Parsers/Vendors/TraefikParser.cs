using System.Globalization;
using System.Text.Json;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// Traefik access logs in JSON format (Pangolin's default), whether forwarded by rsyslog's imfile
/// (syslog header + JSON body) or read as bare JSON lines. Produces <c>traefik.access</c> with ECS
/// <c>http.*</c>, <c>url.*</c>, <c>user_agent.*</c> and <c>source.*</c> fields.
/// <para>
/// Requests no router matched (scanners probing hostnames or paths you don't serve) get
/// <c>event.action=unrouted</c>; everything else is <c>proxied</c>.
/// </para>
/// </summary>
public sealed class TraefikParser : IEventParser
{
    public const string Module = "traefik";
    public const string AccessDataset = "traefik.access";

    public string Dataset => AccessDataset;
    public int Priority => 90;

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var m = envelope.Message;
        return m.Contains("\"DownstreamStatus\"", StringComparison.Ordinal) && m.Contains("\"RequestHost\"", StringComparison.Ordinal);
    }

    public bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        logEvent = null;
        var hasHeader = SyslogParser.TryParseHeader(envelope.Message, envelope.ReceivedAt, out var header);
        var body = hasHeader ? header.Message : envelope.Message;
        var start = body.IndexOf('{', StringComparison.Ordinal);
        if (start < 0)
        {
            return false;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body.AsMemory(start));
        }
        catch (JsonException)
        {
            return false;
        }

        using (doc)
        {
            var j = doc.RootElement;
            if (j.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var status = Int(j, "DownstreamStatus");
            var method = Str(j, "RequestMethod");
            var domain = Str(j, "RequestHost") ?? Str(j, "RequestAddr");
            var target = Str(j, "RequestPath") ?? string.Empty;
            var router = Str(j, "RouterName");
            var durationNs = Long(j, "Duration");

            var e = new LogEvent
            {
                TenantId = tenantId,
                Timestamp = Time(j) ?? (hasHeader ? header.Timestamp : envelope.ReceivedAt),
                HostName = hasHeader ? header.Hostname : string.Empty,
                ObserverIp = envelope.SourceAddress ?? string.Empty,
                EventDataset = AccessDataset,
                EventModule = Module,
                EventAction = router is null ? "unrouted" : "proxied",
                EventOutcome = status is null ? "unknown" : status < 400 ? "success" : "failure",
                LogLevel = status switch { >= 500 => "error", >= 400 => "warning", _ => "informational" },
                SourceIp = Str(j, "ClientHost") ?? string.Empty,
                SourcePort = ushort.TryParse(Str(j, "ClientPort"), NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : (ushort)0,
                NetworkProtocol = "http",
                NetworkTransport = "tcp",
                UserName = Str(j, "ClientUsername") is { } user && user != "-" ? user : string.Empty,
                Raw = envelope.Message,
            };

            var f = e.Fields;
            f["observer.vendor"] = "Traefik";
            f["observer.product"] = "Traefik";
            f["event.category"] = "web";
            if (hasHeader && header.AppName.Length > 0)
            {
                f["process.name"] = header.AppName;
            }

            Set(f, "http.request.method", method);
            if (status is { } code)
            {
                f["http.response.status_code"] = code.ToString(CultureInfo.InvariantCulture);
            }
            Set(f, "http.version", Str(j, "RequestProtocol") is { } protocol && protocol.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ? protocol[5..] : null);
            SetNumber(f, "http.response.body.bytes", Long(j, "DownstreamContentSize"));
            SetNumber(f, "http.request.body.bytes", Long(j, "RequestContentSize"));

            Set(f, "url.domain", domain);
            Set(f, "url.scheme", Str(j, "RequestScheme"));
            if (target.Length > 0)
            {
                f["url.original"] = target;
                var query = target.IndexOf('?', StringComparison.Ordinal);
                f["url.path"] = query < 0 ? target : target[..query];
                if (query >= 0 && query < target.Length - 1)
                {
                    f["url.query"] = target[(query + 1)..];
                }
            }

            Set(f, "user_agent.original", Str(j, "request_User-Agent"));
            Set(f, "http.request.referrer", Str(j, "request_Referer"));
            Set(f, "tls.version", Str(j, "TLSVersion"));
            Set(f, "tls.cipher", Str(j, "TLSCipher"));
            SetNumber(f, "event.duration", durationNs);

            Set(f, "traefik.entrypoint", Str(j, "entryPointName"));
            Set(f, "traefik.router.name", router);
            Set(f, "traefik.service.name", Str(j, "ServiceName"));
            Set(f, "traefik.service.url", Str(j, "ServiceURL"));
            if (Int(j, "OriginStatus") is { } origin && origin > 0)
            {
                f["traefik.origin.status_code"] = origin.ToString(CultureInfo.InvariantCulture);
            }
            if (Int(j, "RetryAttempts") is { } retries && retries > 0)
            {
                f["traefik.retry_attempts"] = retries.ToString(CultureInfo.InvariantCulture);
            }
            if (PangolinResource(router) is { } resource)
            {
                f["pangolin.resource.name"] = resource;
            }

            var ms = durationNs is { } ns ? $" {ns / 1_000_000.0:0.#} ms" : string.Empty;
            e.Message = $"{method} {domain}{target} {status?.ToString(CultureInfo.InvariantCulture) ?? "-"}{ms}".Trim();
            logEvent = e;
            return true;
        }
    }

    /// <summary>
    /// Pangolin names routers <c>&lt;id&gt;-&lt;resource&gt;-router@http</c>; the middle is the resource name
    /// (with dots as dashes), e.g. <c>17-rmm-console-example-router@http</c> → <c>rmm-console-example</c>.
    /// </summary>
    public static string? PangolinResource(string? router)
    {
        if (router is null)
        {
            return null;
        }
        var name = router.Split('@')[0];
        var dash = name.IndexOf('-', StringComparison.Ordinal);
        if (dash <= 0 || !name[..dash].All(char.IsAsciiDigit) || !name.EndsWith("-router", StringComparison.Ordinal))
        {
            return null;
        }
        var resource = name[(dash + 1)..^"-router".Length];
        return resource.Length > 0 ? resource : null;
    }

    private static DateTimeOffset? Time(JsonElement j)
    {
        foreach (var name in (string[])["StartUTC", "time"])
        {
            if (Str(j, name) is { } text &&
                DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            {
                return t;
            }
        }
        return null;
    }

    private static string? Str(JsonElement j, string name) =>
        j.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;

    private static long? Long(JsonElement j, string name) =>
        j.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;

    private static int? Int(JsonElement j, string name) =>
        Long(j, name) is { } n && n is >= int.MinValue and <= int.MaxValue ? (int)n : null;

    private static void Set(Dictionary<string, string> fields, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            fields[key] = value;
        }
    }

    private static void SetNumber(Dictionary<string, string> fields, string key, long? value)
    {
        if (value is { } n)
        {
            fields[key] = n.ToString(CultureInfo.InvariantCulture);
        }
    }
}
