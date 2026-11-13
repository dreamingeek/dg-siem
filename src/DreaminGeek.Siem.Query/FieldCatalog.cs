using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Query;

internal enum SqlType
{
    String,
    Number,
    DateTime,
    Bool,
    Array,
}

internal sealed record SqlExpr(string Sql, SqlType Type);

/// <summary>Maps ECS field names (and friendly aliases) to ClickHouse columns or the <c>fields</c> map.</summary>
internal static class FieldCatalog
{
    private static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["_time"] = "@timestamp",
        ["timestamp"] = "@timestamp",
        ["time"] = "@timestamp",
        ["_raw"] = "raw",
        ["dataset"] = EcsField.EventDataset,
        ["sourcetype"] = EcsField.EventDataset,
        ["module"] = EcsField.EventModule,
        ["action"] = EcsField.EventAction,
        ["outcome"] = EcsField.EventOutcome,
        ["host"] = EcsField.HostName,
        ["observer"] = EcsField.ObserverIp,
        ["level"] = EcsField.LogLevel,
        ["severity"] = EcsField.LogLevel,
        ["src"] = EcsField.SourceIp,
        ["src_ip"] = EcsField.SourceIp,
        ["sport"] = EcsField.SourcePort,
        ["src_port"] = EcsField.SourcePort,
        ["dst"] = EcsField.DestinationIp,
        ["dest"] = EcsField.DestinationIp,
        ["dst_ip"] = EcsField.DestinationIp,
        ["dport"] = EcsField.DestinationPort,
        ["dst_port"] = EcsField.DestinationPort,
        ["dest_port"] = EcsField.DestinationPort,
        ["proto"] = EcsField.NetworkTransport,
        ["transport"] = EcsField.NetworkTransport,
        ["user"] = EcsField.UserName,
        ["msg"] = EcsField.Message,
        ["app"] = "process.name",
        ["program"] = "process.name",
        ["status"] = "http.response.status_code",
        ["method"] = "http.request.method",
        ["domain"] = "url.domain",
        ["vhost"] = "url.domain",
        ["path"] = "url.path",
        ["uri"] = "url.original",
        ["useragent"] = "user_agent.original",
        ["ua"] = "user_agent.original",
        ["resource"] = "pangolin.resource.name",
        ["country"] = "source.geo.country_iso_code",
        ["city"] = "source.geo.city_name",
        ["asn"] = "source.as.number",
        ["as_org"] = "source.as.organization.name",
        ["org"] = "source.as.organization.name",
        ["dst_country"] = "destination.geo.country_iso_code",
        ["dst_org"] = "destination.as.organization.name",
        ["threat_feed"] = "threat.feed.name",
        ["threat_ip"] = "threat.enrichments.indicator.ip",
        ["threat_on"] = "threat.enrichments.matched.field",
        ["threat_reason"] = "threat.enrichments.indicator.description",
        ["tenant_id"] = "tenant",
        ["_id"] = "event.id",
    };

    private static readonly Dictionary<string, SqlExpr> Columns = new(StringComparer.Ordinal)
    {
        ["@timestamp"] = new("timestamp", SqlType.DateTime),
        [EcsField.EventIngested] = new("ingest_time", SqlType.DateTime),
        ["tenant"] = new("tenant_id", SqlType.String),
        ["event.id"] = new("toString(event_id)", SqlType.String),
        ["raw"] = new("raw", SqlType.String),
        ["_fields"] = new("fields", SqlType.Array), // the whole map of non-promoted fields (event details)
        [EcsField.Message] = new("message", SqlType.String),
        [EcsField.HostName] = new("host_name", SqlType.String),
        [EcsField.ObserverIp] = new("observer_ip", SqlType.String),
        [EcsField.EventDataset] = new("event_dataset", SqlType.String),
        [EcsField.EventModule] = new("event_module", SqlType.String),
        [EcsField.EventAction] = new("event_action", SqlType.String),
        [EcsField.EventOutcome] = new("event_outcome", SqlType.String),
        [EcsField.LogLevel] = new("log_level", SqlType.String),
        [EcsField.SourceIp] = new("source_ip", SqlType.String),
        [EcsField.SourcePort] = new("source_port", SqlType.Number),
        [EcsField.DestinationIp] = new("destination_ip", SqlType.String),
        [EcsField.DestinationPort] = new("destination_port", SqlType.Number),
        [EcsField.NetworkProtocol] = new("network_protocol", SqlType.String),
        [EcsField.NetworkTransport] = new("network_transport", SqlType.String),
        [EcsField.UserName] = new("user_name", SqlType.String),
    };

    /// <summary>Columns shown for raw-event results when the query doesn't choose its own.</summary>
    public static readonly string[] DefaultEventColumns =
        ["@timestamp", "tenant", EcsField.HostName, EcsField.EventDataset, EcsField.LogLevel, EcsField.Message, "event.id"];

    /// <summary>Fields summarized by <c>fieldsummary</c> when none are named (the search page's sidebar).</summary>
    public static readonly string[] DefaultSummaryFields =
    [
        EcsField.EventDataset, EcsField.HostName, EcsField.SourceIp, EcsField.DestinationIp, EcsField.DestinationPort,
        EcsField.EventAction, EcsField.UserName, EcsField.LogLevel, "process.name", EcsField.ObserverIp,
    ];

    /// <summary>Built-in fields and shortcuts for autocomplete: (name, description).</summary>
    public static IEnumerable<(string Name, string Detail)> Suggestable() =>
        Columns.Keys.Where(k => k != "_fields")
            .OrderBy(k => BackgroundColumns.Contains(k)) // stable: keeps catalog order otherwise
            .Select(k => (k, "built-in field"))
            .Concat(Aliases.Where(a => !a.Key.StartsWith('_')).Select(a => (a.Key, $"shortcut for {a.Value}")));

    /// <summary>Columns rarely filtered or grouped on; listed last in suggestions.</summary>
    private static readonly HashSet<string> BackgroundColumns =
        new(["@timestamp", EcsField.EventIngested, "event.id", "raw", "tenant"], StringComparer.Ordinal);

    /// <summary>Resolves a friendly alias (<c>src</c>) to its ECS name (<c>source.ip</c>).</summary>
    public static string Canonical(string name) => Aliases.GetValueOrDefault(name, name);

    public static bool IsValidName(string name) =>
        name.Length is > 0 and <= 128 && (Lexer.IsWordStart(name[0]) || name[0] == '@') &&
        name.All(c => Lexer.IsWordChar(c) || c is '.' or '-');

    /// <summary>SQL for an event field: a promoted column, or a lookup in the <c>fields</c> map.</summary>
    public static SqlExpr Resolve(string canonicalName, Func<object, string, string> param) =>
        Columns.TryGetValue(canonicalName, out var column)
            ? column
            : new SqlExpr($"fields[{param(canonicalName, "String")}]", SqlType.String);

    public static bool IsIpField(string canonicalName) =>
        canonicalName is EcsField.SourceIp or EcsField.DestinationIp or EcsField.ObserverIp || canonicalName.EndsWith(".ip", StringComparison.Ordinal);
}
