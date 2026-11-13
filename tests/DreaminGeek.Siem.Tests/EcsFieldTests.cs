using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Tests;

public class EcsFieldTests
{
    [Theory]
    [InlineData(EcsField.SourceIp, "source_ip")]
    [InlineData(EcsField.EventDataset, "event_dataset")]
    [InlineData(EcsField.Timestamp, "timestamp")]
    [InlineData(EcsField.EventIngested, "ingest_time")]
    [InlineData(EcsField.UserName, "user_name")]
    public void Maps_ecs_names_to_clickhouse_columns(string ecs, string column) =>
        Assert.Equal(column, EcsField.ToColumn(ecs));
}
