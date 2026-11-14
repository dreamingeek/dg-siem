using ClickHouse.Driver;
using DreaminGeek.Siem.Core;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

/// <summary>Batch-inserts metric samples (006_metrics.sql) with RowBinary over HTTP.</summary>
public sealed class ClickHouseMetricSink(ClickHouseClient client, IOptions<ClickHouseOptions> options) : IMetricSink
{
    private static readonly string[] Columns = ["tenant_id", "timestamp", "name", "labels", "value", "type"];

    private readonly string _table = $"{options.Value.Database}.metrics";

    public async Task WriteAsync(IReadOnlyList<MetricSample> batch, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (batch.Count == 0)
        {
            return;
        }
        var rows = batch.Select(m => new object[]
        {
            // Labels arrive sorted, and stay in that order: the series hash is taken over the map as written.
            m.TenantId, m.Timestamp.UtcDateTime, m.Name, new Dictionary<string, string>(m.Labels, StringComparer.Ordinal), m.Value, m.Type,
        });
        await client.InsertBinaryAsync(_table, Columns, rows, cancellationToken: cancellationToken);
    }
}
