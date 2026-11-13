using System.Collections.Concurrent;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Ingest;
using DreaminGeek.Siem.Parsers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Tests;

public sealed class IngestPipelineTests
{
    /// <summary>Fails its first <c>failures</c> writes (an event store restarting), then stores everything.</summary>
    private sealed class FlakySink(int failures) : IEventSink
    {
        private int _calls;

        public ConcurrentQueue<LogEvent> Events { get; } = new();

        public Task WriteAsync(IReadOnlyList<LogEvent> batch, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _calls) <= failures)
            {
                throw new HttpRequestException("Connection refused (127.0.0.1:8123)");
            }
            foreach (var e in batch)
            {
                Events.Enqueue(e);
            }
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Failed_writes_are_retried_not_dropped_and_new_batches_wait_meanwhile()
    {
        var sink = new FlakySink(failures: 2);
        var pipeline = new IngestPipeline(new ParserRegistry([new SyslogParser()]), sink, new DropFilter(new NoDropRules()), new DreaminGeek.Siem.Ingest.GeoIp.NoGeoIp(),
            Options.Create(new IngestOptions { FlushInterval = TimeSpan.FromMilliseconds(50) }), NullLogger<IngestPipeline>.Instance);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await pipeline.StartAsync(cts.Token);
        Assert.True(pipeline.Accepting);

        await pipeline.EnqueueAsync("dg", Enumerable.Range(0, 5).Select(i => new RawEnvelope(DateTimeOffset.UtcNow, "syslog-udp", "10.0.0.1", $"<13>Nov 13 01:00:00 fw app: line {i}")), cts.Token);

        // The first write fails: the server stops taking batches and says why.
        while (pipeline.Status.FailingSince is null && !cts.IsCancellationRequested)
        {
            await Task.Delay(10, cts.Token);
        }
        Assert.False(pipeline.Accepting);
        Assert.Contains("Connection refused", pipeline.Status.LastError, StringComparison.Ordinal);

        // It retries the same batch (after 2 s, then 4 s) until the store is back, then takes batches again.
        while (sink.Events.Count < 5 && !cts.IsCancellationRequested)
        {
            await Task.Delay(50, cts.Token);
        }
        Assert.Equal(5, sink.Events.Count);
        Assert.True(pipeline.Accepting);
        Assert.Null(pipeline.Status.FailingSince);
        Assert.Equal(5, pipeline.Status.Written);

        await pipeline.StopAsync(CancellationToken.None);
    }
}
