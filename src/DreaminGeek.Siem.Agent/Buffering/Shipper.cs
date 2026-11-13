using DreaminGeek.Siem.Agent.Server;

namespace DreaminGeek.Siem.Agent.Buffering;

/// <summary>Sends sealed segments oldest-first, deleting each once the server accepts it.</summary>
public sealed partial class Shipper(DiskBuffer buffer, ServerClient server, ILogger<Shipper> logger)
{
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(60);

    public async Task RunAsync(CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            var segments = buffer.SealedSegments();
            if (segments.Count == 0)
            {
                await buffer.WaitForSegmentAsync(TimeSpan.FromSeconds(2), ct);
                continue;
            }

            var segment = segments[0];
            byte[] body;
            int count;
            try
            {
                body = ServerClient.Gzip(DiskBuffer.BuildBatchJson(segment, out count));
            }
            catch (FileNotFoundException)
            {
                continue; // evicted by the size cap meanwhile
            }

            if (count == 0)
            {
                DiskBuffer.Complete(segment);
                continue;
            }

            var (result, status) = await server.ShipAsync(body, ct);
            switch (result)
            {
                case ShipResult.Accepted:
                    DiskBuffer.Complete(segment);
                    backoff = TimeSpan.FromSeconds(1);
                    LogShipped(logger, count, segments.Count - 1);
                    break;
                case ShipResult.Rejected:
                    buffer.Reject(segment);
                    LogRejected(logger, count, (int?)status, Path.GetFileName(segment));
                    break;
                case ShipResult.Unauthorized:
                    LogUnauthorized(logger, (int?)status, backoff);
                    await Task.Delay(backoff, ct);
                    backoff = Next(backoff);
                    break;
                default:
                    if (logger.IsEnabled(LogLevel.Warning))
                    {
                        LogRetry(logger, status is null ? "no response" : $"HTTP {(int)status}", segments.Count, backoff);
                    }
                    await Task.Delay(backoff, ct);
                    backoff = Next(backoff);
                    break;
            }
        }
    }

    private static TimeSpan Next(TimeSpan current) => current * 2 > MaxBackoff ? MaxBackoff : current * 2;

    [LoggerMessage(Level = LogLevel.Debug, Message = "Shipped {Count} events; {Pending} segments pending")]
    private static partial void LogShipped(ILogger logger, int count, int pending);

    [LoggerMessage(Level = LogLevel.Error, Message = "Server rejected a batch of {Count} events (HTTP {Status}); moved {Segment} to buffer/rejected")]
    private static partial void LogRejected(ILogger logger, int count, int? status, string segment);

    [LoggerMessage(Level = LogLevel.Error, Message = "Server refused this agent (HTTP {Status}). Revoked or replaced? Data is kept; retrying in {Backoff}")]
    private static partial void LogUnauthorized(ILogger logger, int? status, TimeSpan backoff);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Server unavailable ({Status}); {Pending} segments buffered, retrying in {Backoff}")]
    private static partial void LogRetry(ILogger logger, string status, int pending, TimeSpan backoff);
}
