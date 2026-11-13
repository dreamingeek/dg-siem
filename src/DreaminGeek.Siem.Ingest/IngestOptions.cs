namespace DreaminGeek.Siem.Ingest;

public sealed class IngestOptions
{
    public const string SectionName = "Ingest";

    /// <summary>Max events buffered in memory before the ingest API starts applying backpressure.</summary>
    public int QueueCapacity { get; set; } = 200_000;

    /// <summary>Flush to ClickHouse when this many events are pending...</summary>
    public int BatchSize { get; set; } = 10_000;

    /// <summary>...or when this much time has passed since the first pending event.</summary>
    public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(1);
}
