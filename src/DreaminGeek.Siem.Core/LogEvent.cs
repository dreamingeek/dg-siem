namespace DreaminGeek.Siem.Core;

/// <summary>
/// A parsed, normalized event ready to be written to storage. Promoted ECS fields are
/// first-class properties; everything else goes in <see cref="Fields"/>.
/// </summary>
public sealed class LogEvent
{
    public required string TenantId { get; init; }
    public required DateTimeOffset Timestamp { get; set; }
    public DateTimeOffset IngestTime { get; set; } = DateTimeOffset.UtcNow;

    public string HostName { get; set; } = string.Empty;
    public string ObserverIp { get; set; } = string.Empty;

    public string EventDataset { get; set; } = "generic";
    public string EventModule { get; set; } = string.Empty;
    public string EventAction { get; set; } = string.Empty;
    public string EventOutcome { get; set; } = string.Empty;

    public string LogLevel { get; set; } = string.Empty;

    public string SourceIp { get; set; } = string.Empty;
    public ushort SourcePort { get; set; }
    public string DestinationIp { get; set; } = string.Empty;
    public ushort DestinationPort { get; set; }
    public string NetworkProtocol { get; set; } = string.Empty;
    public string NetworkTransport { get; set; } = string.Empty;

    public string UserName { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;
    public required string Raw { get; init; }

    /// <summary>Days to keep this event (ClickHouse deletes it after); 0 = the table default. Set at ingest from <see cref="RetentionPolicy"/>.</summary>
    public ushort RetentionDays { get; set; }

    /// <summary>Non-promoted fields keyed by ECS name (or vendor-specific <c>module.*</c> names).</summary>
    public Dictionary<string, string> Fields { get; } = new(StringComparer.Ordinal);
}
