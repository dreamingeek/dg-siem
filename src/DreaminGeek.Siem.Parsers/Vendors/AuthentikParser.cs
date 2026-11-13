using System.Globalization;
using System.Text.Json;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// authentik's JSON logs (server, worker and outposts), as journald → rsyslog forwards them.
/// <list type="bullet">
/// <item><c>authentik.event</c>: audit events (<c>"Created Event"</c>): logins, failed logins, logouts, password
/// changes, app authorizations, impersonation, exceptions. <c>event.action</c> is authentik's action
/// (<c>login</c>, <c>login_failed</c>, …), with the user, client IP, GeoIP/ASN and the HTTP request.</item>
/// <item><c>authentik.http</c>: requests served by the server or an outpost (method, path, status, client).</item>
/// <item><c>authentik.tasks</c>: routine background-task chatter ("Task started", "Sent 0 scheduled tasks"),
/// split out so a drop rule can discard it; task errors stay in <c>authentik.server</c>.</item>
/// <item><c>authentik.outpost</c> / <c>authentik.server</c>: everything else.</item>
/// </list>
/// </summary>
public sealed class AuthentikParser : IEventParser
{
    public const string Module = "authentik";

    public string Dataset => "authentik";
    public int Priority => 95;

    private static readonly HashSet<string> FailureActions = new(StringComparer.Ordinal)
    {
        "login_failed", "suspicious_request", "policy_exception", "property_mapping_exception",
        "system_task_exception", "system_exception", "configuration_error", "access_request_denied",
        "authenticator_locked",
    };

    private static readonly HashSet<string> ErrorActions = new(StringComparer.Ordinal)
    {
        "policy_exception", "property_mapping_exception", "system_task_exception", "system_exception", "configuration_error",
    };

    private static readonly HashSet<string> WarningActions = new(StringComparer.Ordinal)
    {
        "login_failed", "suspicious_request", "impersonation_started", "authenticator_locked", "configuration_warning",
    };

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var m = envelope.Message;
        return m.Contains("authentik", StringComparison.Ordinal) && m.Contains("\"event\"", StringComparison.Ordinal);
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
            if (j.ValueKind != JsonValueKind.Object || Str(j, "event") is not { } text)
            {
                return false;
            }
            var logger = Str(j, "logger") ?? Str(j, "target") ?? string.Empty;
            if (!logger.StartsWith("authentik", StringComparison.Ordinal) && !logger.StartsWith("django", StringComparison.Ordinal)
                && !logger.StartsWith("sqlx", StringComparison.Ordinal) && !(hasHeader && header.AppName.Contains("authentik", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            var e = new LogEvent
            {
                TenantId = tenantId,
                // The syslog header carries the zone; authentik's own "timestamp" is UTC from Python but local from the Rust outpost.
                Timestamp = hasHeader ? header.Timestamp : Time(j) ?? envelope.ReceivedAt,
                HostName = hasHeader ? header.Hostname : string.Empty,
                ObserverIp = envelope.SourceAddress ?? string.Empty,
                EventModule = Module,
                LogLevel = Level(Str(j, "level")),
                Message = text,
                Raw = envelope.Message,
            };
            var f = e.Fields;
            f["observer.vendor"] = "authentik";
            f["observer.product"] = "authentik";
            if (logger.Length > 0)
            {
                f["authentik.logger"] = logger;
            }
            if (hasHeader && header.AppName.Length > 0)
            {
                f["process.name"] = header.AppName;
            }
            if (Num(j, "pid") is { } pid)
            {
                f["process.pid"] = pid.ToString(CultureInfo.InvariantCulture);
            }
            Set(f, "http.request.id", Str(j, "request_id"));

            if (text == "Created Event" && Str(j, "action") is { } action)
            {
                MapAuditEvent(j, action, e);
            }
            else if (Num(j, "status") is { } status && Str(j, "method") is { } method)
            {
                MapRequest(j, (int)status, method, text, e);
            }
            else if (logger.StartsWith("authentik::outpost", StringComparison.Ordinal) || logger.StartsWith("authentik.outpost", StringComparison.Ordinal))
            {
                e.EventDataset = "authentik.outpost";
                Set(f, "url.domain", Str(j, "host"));
            }
            else if (IsTaskChatter(logger, e.LogLevel, j))
            {
                e.EventDataset = "authentik.tasks";
                Set(f, "authentik.task.name", Str(j, "task_name"));
            }
            else
            {
                e.EventDataset = "authentik.server";
                Set(f, "authentik.task.name", Str(j, "task_name"));
                Set(f, "error.message", Str(j, "exc"));
            }

            logEvent = e;
            return true;
        }
    }

    private static void MapAuditEvent(JsonElement j, string action, LogEvent e)
    {
        var f = e.Fields;
        e.EventDataset = "authentik.event";
        e.EventAction = action;
        e.EventOutcome = FailureActions.Contains(action) ? "failure" : "success";
        e.LogLevel = ErrorActions.Contains(action) ? "error" : WarningActions.Contains(action) ? "warning" : "informational";
        f["event.category"] = action switch
        {
            "login" or "login_failed" or "logout" or "authenticator_locked" or "authenticator_unlocked" => "authentication",
            "user_write" or "password_set" or "model_created" or "model_updated" or "model_deleted"
                or "impersonation_started" or "impersonation_ended" or "source_linked" => "iam",
            "configuration_error" or "configuration_warning" => "configuration",
            _ => "process",
        };

        var ip = Str(j, "client_ip");
        if (ip is not null && ip != "255.255.255.255")
        {
            e.SourceIp = ip;
        }

        var context = j.TryGetProperty("context", out var c) && c.ValueKind == JsonValueKind.Object ? c : default;
        var user = j.TryGetProperty("user", out var u) && u.ValueKind == JsonValueKind.Object ? u : default;
        var anonymous = user.ValueKind == JsonValueKind.Object && user.TryGetProperty("is_anonymous", out var anon) && anon.ValueKind == JsonValueKind.True;
        // A failed login is logged as the anonymous user; the name that was tried is in the context.
        var username = (!anonymous && user.ValueKind == JsonValueKind.Object ? Str(user, "username") : null)
            ?? (context.ValueKind == JsonValueKind.Object ? Str(context, "username") : null);
        if (username is not null)
        {
            e.UserName = username;
        }
        if (!anonymous && user.ValueKind == JsonValueKind.Object)
        {
            Set(f, "user.email", Str(user, "email"));
            if (user.TryGetProperty("on_behalf_of", out var behalf) && behalf.ValueKind == JsonValueKind.Object)
            {
                Set(f, "user.effective.name", Str(behalf, "username"));
            }
            if (user.TryGetProperty("authenticated_as", out var actual) && actual.ValueKind == JsonValueKind.Object)
            {
                Set(f, "authentik.authenticated_as", Str(actual, "username"));
            }
        }

        if (context.ValueKind == JsonValueKind.Object)
        {
            if (context.TryGetProperty("http_request", out var http) && http.ValueKind == JsonValueKind.Object)
            {
                Set(f, "url.path", Str(http, "path"));
                Set(f, "http.request.method", Str(http, "method"));
                Set(f, "user_agent.original", Str(http, "user_agent"));
                Set(f, "http.request.id", Str(http, "request_id"));
            }
            if (context.TryGetProperty("geo", out var geo) && geo.ValueKind == JsonValueKind.Object)
            {
                Set(f, "source.geo.country_iso_code", Str(geo, "country"));
                Set(f, "source.geo.city_name", Str(geo, "city"));
                Set(f, "source.geo.continent_code", Str(geo, "continent"));
            }
            if (context.TryGetProperty("asn", out var asn) && asn.ValueKind == JsonValueKind.Object)
            {
                if (Num(asn, "asn") is { } number)
                {
                    f["source.as.number"] = number.ToString(CultureInfo.InvariantCulture);
                }
                Set(f, "source.as.organization.name", Str(asn, "as_org"));
            }
            if (context.TryGetProperty("stage", out var stage) && stage.ValueKind == JsonValueKind.Object)
            {
                Set(f, "authentik.stage.name", Str(stage, "name"));
            }
            Set(f, "authentik.auth_method", Str(context, "auth_method"));
            Set(f, "error.message", Str(context, "message"));
            if (context.TryGetProperty("authorized_application", out var app) && app.ValueKind == JsonValueKind.Object)
            {
                Set(f, "authentik.application.name", Str(app, "name"));
            }
        }

        var who = username is null ? string.Empty : $" {username}";
        var from = e.SourceIp.Length > 0 ? $" from {e.SourceIp}" : string.Empty;
        var detail = f.TryGetValue("authentik.application.name", out var appName) ? $" to {appName}"
            : f.TryGetValue("error.message", out var error) ? $": {error}"
            : string.Empty;
        e.Message = $"{action}{who}{from}{detail}";
    }

    private static void MapRequest(JsonElement j, int status, string method, string path, LogEvent e)
    {
        var f = e.Fields;
        e.EventDataset = "authentik.http";
        e.NetworkProtocol = "http";
        e.EventOutcome = status < 400 ? "success" : "failure";
        e.LogLevel = status switch { >= 500 => "error", >= 400 => "warning", _ => e.LogLevel };
        f["event.category"] = "web";
        f["http.request.method"] = method;
        f["http.response.status_code"] = status.ToString(CultureInfo.InvariantCulture);
        var query = path.IndexOf('?', StringComparison.Ordinal);
        f["url.original"] = path;
        f["url.path"] = query < 0 ? path : path[..query];
        Set(f, "url.domain", Str(j, "host"));
        Set(f, "url.scheme", Str(j, "scheme"));
        Set(f, "user_agent.original", Str(j, "user_agent"));
        if (Str(j, "remote") is { } remote)
        {
            e.SourceIp = remote;
        }
        if (Str(j, "user") is { } user)
        {
            e.UserName = user;
        }
        // Server logs "runtime" in ms; the Go outpost logs "took-ms".
        if ((Num(j, "runtime") ?? Num(j, "took-ms")) is { } ms)
        {
            f["event.duration"] = ((long)(ms * 1_000_000)).ToString(CultureInfo.InvariantCulture);
        }
        e.Message = $"{method} {path} {status}";
    }

    /// <summary>Routine scheduler/worker bookkeeping, logged every minute; errors are not chatter.</summary>
    private static bool IsTaskChatter(string logger, string level, JsonElement j) =>
        level is "informational" or "debug" &&
        (logger.StartsWith("authentik.tasks", StringComparison.Ordinal) || logger.StartsWith("django_dramatiq", StringComparison.Ordinal)) &&
        (!j.TryGetProperty("exc", out var exc) || exc.ValueKind == JsonValueKind.Null);

    private static string Level(string? level) => level?.ToLowerInvariant() switch
    {
        "debug" or "trace" => "debug",
        "warn" or "warning" => "warning",
        "error" => "error",
        "critical" or "fatal" => "critical",
        _ => "informational",
    };

    private static DateTimeOffset? Time(JsonElement j) =>
        Str(j, "timestamp") is { } text &&
        DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
            ? t : null;

    private static string? Str(JsonElement j, string name) =>
        j.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;

    private static double? Num(JsonElement j, string name) =>
        j.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var n) ? n : null;

    private static void Set(Dictionary<string, string> fields, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            fields[key] = value;
        }
    }
}
