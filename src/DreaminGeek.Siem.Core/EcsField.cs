namespace DreaminGeek.Siem.Core;

/// <summary>
/// ECS (Elastic Common Schema) field names used throughout DG SIEM.
/// The query language and UI use the dotted ECS names; ClickHouse stores them as
/// underscore-separated columns (see <see cref="ToColumn"/>).
/// Anything not promoted to a column lives in the <c>fields</c> map under its ECS name.
/// </summary>
public static class EcsField
{
    public const string Timestamp = "@timestamp";
    public const string Message = "message";

    public const string HostName = "host.name";
    public const string ObserverIp = "observer.ip";

    public const string EventDataset = "event.dataset";   // our "sourcetype", e.g. unifi.firewall
    public const string EventModule = "event.module";     // e.g. unifi, traefik, crowdsec
    public const string EventAction = "event.action";
    public const string EventOutcome = "event.outcome";   // success | failure | unknown
    public const string EventIngested = "event.ingested";

    public const string LogLevel = "log.level";

    public const string SourceIp = "source.ip";
    public const string SourcePort = "source.port";
    public const string DestinationIp = "destination.ip";
    public const string DestinationPort = "destination.port";
    public const string NetworkProtocol = "network.protocol";   // application layer: dns, http, ...
    public const string NetworkTransport = "network.transport"; // tcp, udp, icmp, ...

    public const string UserName = "user.name";

    /// <summary>Fields that have dedicated ClickHouse columns.</summary>
    public static readonly IReadOnlySet<string> Promoted = new HashSet<string>(StringComparer.Ordinal)
    {
        Timestamp, Message, HostName, ObserverIp, EventDataset, EventModule, EventAction,
        EventOutcome, EventIngested, LogLevel, SourceIp, SourcePort, DestinationIp,
        DestinationPort, NetworkProtocol, NetworkTransport, UserName,
    };

    /// <summary>Maps an ECS name to its ClickHouse column, e.g. <c>source.ip</c> → <c>source_ip</c>.</summary>
    public static string ToColumn(string ecsName) => ecsName switch
    {
        Timestamp => "timestamp",
        EventIngested => "ingest_time",
        _ => ecsName.Replace('.', '_'),
    };
}
