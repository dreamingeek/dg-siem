using ClickHouse.Driver;
using DreaminGeek.Siem.Core;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

/// <summary>Batch-inserts events with RowBinary over HTTP. Callers should batch (~10k rows or ~1s).</summary>
public sealed class ClickHouseEventSink(ClickHouseClient client, IOptions<ClickHouseOptions> options) : IEventSink
{
    private static readonly string[] Columns =
    [
        "tenant_id", "timestamp", "ingest_time", "host_name", "observer_ip",
        "event_dataset", "event_module", "event_action", "event_outcome", "log_level",
        "source_ip", "source_port", "destination_ip", "destination_port", "network_protocol", "network_transport",
        "user_name", "message", "raw", "fields", "retention_days",
    ];

    /// <summary>The column default in 004_retention.sql, for events that weren't given a retention.</summary>
    private const ushort DefaultRetentionDays = 120;

    private readonly string _table = $"{options.Value.Database}.events";

    public async Task WriteAsync(IReadOnlyList<LogEvent> batch, CancellationToken cancellationToken)
    {
        if (batch.Count == 0)
        {
            return;
        }

        var rows = batch.Select(e => new object[]
        {
            e.TenantId, e.Timestamp.UtcDateTime, e.IngestTime.UtcDateTime, e.HostName, e.ObserverIp,
            e.EventDataset, e.EventModule, e.EventAction, e.EventOutcome, e.LogLevel,
            e.SourceIp, e.SourcePort, e.DestinationIp, e.DestinationPort, e.NetworkProtocol, e.NetworkTransport,
            e.UserName, e.Message, e.Raw, e.Fields, e.RetentionDays == 0 ? DefaultRetentionDays : e.RetentionDays,
        });

        await client.InsertBinaryAsync(_table, Columns, rows, cancellationToken: cancellationToken);
    }
}
