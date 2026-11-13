using System.Threading.Channels;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Ingest;

/// <summary>
/// receive → parse → batch → write. The ingest API calls <see cref="EnqueueAsync"/>; a single
/// background loop parses and flushes batches to the <see cref="IEventSink"/>.
/// Phase 8 swaps the in-memory channel for NATS JetStream / Redpanda without changing callers.
/// </summary>
public sealed partial class IngestPipeline : BackgroundService
{
    private readonly Channel<(string TenantId, RawEnvelope Envelope)> _queue;
    private readonly ParserRegistry _parsers;
    private readonly IEventSink _sink;
    private readonly DropFilter _drops;
    private readonly DreaminGeek.Siem.Ingest.GeoIp.IGeoIpEnricher _geo;
    private readonly RetentionPolicy _retention;
    private readonly DreaminGeek.Siem.Ingest.ThreatIntel.IThreatIntelEnricher? _threats;
    private readonly IngestOptions _options;
    private readonly ILogger<IngestPipeline> _logger;

    public IngestPipeline(ParserRegistry parsers, IEventSink sink, DropFilter drops, DreaminGeek.Siem.Ingest.GeoIp.IGeoIpEnricher geo, IOptions<IngestOptions> options, ILogger<IngestPipeline> logger, RetentionPolicy? retention = null,
        DreaminGeek.Siem.Ingest.ThreatIntel.IThreatIntelEnricher? threats = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _parsers = parsers;
        _sink = sink;
        _retention = retention ?? new RetentionPolicy();
        _geo = geo;
        _threats = threats;
        _drops = drops;
        _options = options.Value;
        _logger = logger;
        _queue = Channel.CreateBounded<(string, RawEnvelope)>(new BoundedChannelOptions(_options.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });
    }

    private readonly Lock _statusGate = new();
    private DateTimeOffset? _failingSince;
    private string? _lastError;
    private DateTimeOffset? _lastWrite;
    private long _written;

    /// <summary>
    /// Whether to take new batches. Not while writes to the event store fail, nor when the queue is nearly full: the
    /// ingest endpoint then answers 503 and agents keep the events in their disk buffers and resend them later,
    /// instead of the server accepting events it can't store.
    /// </summary>
    public bool Accepting
    {
        get
        {
            lock (_statusGate)
            {
                return _failingSince is null && _queue.Reader.Count < _options.QueueCapacity * 8L / 10;
            }
        }
    }

    public IngestStatus Status
    {
        get
        {
            lock (_statusGate)
            {
                return new IngestStatus(_queue.Reader.Count, _options.QueueCapacity, _failingSince, _lastError, Interlocked.Read(ref _written), _lastWrite);
            }
        }
    }

    /// <summary>Queues a batch from an agent. Awaits (backpressure) when the queue is full.</summary>
    public async ValueTask EnqueueAsync(string tenantId, IEnumerable<RawEnvelope> envelopes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelopes);
        foreach (var envelope in envelopes)
        {
            await _queue.Writer.WriteAsync((tenantId, envelope), cancellationToken);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var batch = new List<LogEvent>(_options.BatchSize);
        var reader = _queue.Reader;
        var attempt = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // A batch that failed to write is retried as it is, before anything new is read.
                if (attempt == 0)
                {
                    if (batch.Count == 0 && !await reader.WaitToReadAsync(stoppingToken))
                    {
                        break;
                    }

                    using var flushTimer = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    flushTimer.CancelAfter(_options.FlushInterval);
                    try
                    {
                        while (batch.Count < _options.BatchSize && await reader.WaitToReadAsync(flushTimer.Token))
                        {
                            while (batch.Count < _options.BatchSize && reader.TryRead(out var item))
                            {
                                var parsed = _parsers.Parse(item.Envelope, item.TenantId);
                                if (_drops.Match(parsed) is null)
                                {
                                    _geo.Enrich(parsed);
                                    _threats?.Enrich(parsed);
                                    parsed.RetentionDays = _retention.DaysFor(parsed.TenantId, parsed.EventDataset);
                                    batch.Add(parsed);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                    {
                        // Flush interval elapsed.
                    }
                }

                await FlushAsync(batch, stoppingToken);
                if (attempt > 0)
                {
                    LogRecovered(_logger, attempt);
                    lock (_statusGate)
                    {
                        _failingSince = null;
                        _lastError = null;
                    }
                    attempt = 0;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // The loop must survive storage outages.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                attempt++;
                lock (_statusGate)
                {
                    _failingSince ??= DateTimeOffset.UtcNow;
                    _lastError = ex.Message.Split('\n', 2)[0].Trim();
                }
                LogFlushFailed(_logger, ex, batch.Count, attempt);
                // Keep the batch and try again: 2, 4, 8, 16, then every 30 seconds.
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, Math.Min(attempt, 5)))), stoppingToken);
            }
        }

        try
        {
            await FlushAsync(batch, CancellationToken.None);
        }
#pragma warning disable CA1031 // Shutting down: nothing more to do than say so.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogShutdownLost(_logger, ex, batch.Count + _queue.Reader.Count);
        }
    }

    private async Task FlushAsync(List<LogEvent> batch, CancellationToken cancellationToken)
    {
        _drops.Flush();
        if (batch.Count == 0)
        {
            return;
        }
        await _sink.WriteAsync(batch, cancellationToken);
        Interlocked.Add(ref _written, batch.Count);
        lock (_statusGate)
        {
            _lastWrite = DateTimeOffset.UtcNow;
        }
        batch.Clear();
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to write a batch of {Count} events (attempt {Attempt}); keeping it and refusing new batches until the event store is back")]
    private static partial void LogFlushFailed(ILogger logger, Exception ex, int count, int attempt);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Writing events again after {Attempts} failed attempts")]
    private static partial void LogRecovered(ILogger logger, int attempts);

    [LoggerMessage(Level = LogLevel.Error, Message = "Shutting down with the event store unavailable: {Count} queued events weren't written")]
    private static partial void LogShutdownLost(ILogger logger, Exception ex, int count);
}

/// <summary>The server's write queue, for Administration &gt; Health.</summary>
/// <param name="FailingSince">When writes to the event store started failing; null while they work.</param>
public sealed record IngestStatus(int Queued, int Capacity, DateTimeOffset? FailingSince, string? LastError, long Written, DateTimeOffset? LastWrite);
