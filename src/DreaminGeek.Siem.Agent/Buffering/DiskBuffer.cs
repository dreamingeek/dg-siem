using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Buffering;

/// <summary>
/// Durable buffer between inputs and the shipper. Inputs call <see cref="TryEnqueue"/> (never blocks:
/// UDP syslog can't be slowed down). A writer appends NDJSON to <c>current.open</c> and seals it to
/// <c>&lt;ticks&gt;.seg</c> by size, count or age. The shipper sends and deletes sealed segments
/// oldest-first. Delivery is at-least-once: a crash between send and delete resends one segment.
/// </summary>
public sealed class DiskBuffer : IDisposable
{
    public const string SegmentExtension = ".seg";
    private const string OpenFile = "current.open";
    private const int MaxSegmentBytes = 4 * 1024 * 1024;

    private readonly string _directory;
    private readonly long _maxBytes;
    private readonly int _maxEvents;
    private readonly TimeSpan _maxAge;
    private readonly Channel<RawEnvelope> _incoming;
    private readonly SemaphoreSlim _sealed = new(0);
    private long _dropped;
    private long _evicted;

    public DiskBuffer(string directory, long maxBytes, int maxEventsPerSegment, TimeSpan maxSegmentAge)
    {
        _directory = directory;
        _maxBytes = maxBytes;
        _maxEvents = maxEventsPerSegment;
        _maxAge = maxSegmentAge;
        Directory.CreateDirectory(directory);
        Directory.CreateDirectory(Path.Combine(directory, "rejected"));
        _incoming = Channel.CreateBounded<RawEnvelope>(new BoundedChannelOptions(100_000)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
        });
        RecoverOpenSegment();
    }

    /// <summary>Events dropped because the in-memory queue was full (disk writer can't keep up).</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>Events in segments deleted because the buffer exceeded its size cap.</summary>
    public long Evicted => Interlocked.Read(ref _evicted);

    public bool TryEnqueue(RawEnvelope envelope)
    {
        if (_incoming.Writer.TryWrite(envelope))
        {
            return true;
        }
        Interlocked.Increment(ref _dropped);
        return false;
    }

    /// <summary>Sealed segments, oldest first.</summary>
    public IReadOnlyList<string> SealedSegments() =>
        Directory.GetFiles(_directory, "*" + SegmentExtension).Order(StringComparer.Ordinal).ToArray();

    /// <summary>The backlog, for the status the agent reports on each config poll.</summary>
    public AgentStatusReport Status()
    {
        long bytes = 0;
        var segments = 0;
        string? oldest = null;
        foreach (var file in new DirectoryInfo(_directory).EnumerateFiles("*" + SegmentExtension))
        {
            try
            {
                bytes += file.Length;
            }
            catch (FileNotFoundException)
            {
                continue; // shipped meanwhile
            }
            segments++;
            if (oldest is null || string.CompareOrdinal(file.Name, oldest) < 0)
            {
                oldest = file.Name;
            }
        }
        // Segment names start with the UTC ticks they were sealed at.
        TimeSpan? age = oldest is not null && long.TryParse(oldest.AsSpan(0, Math.Min(20, oldest.Length)), NumberStyles.None, CultureInfo.InvariantCulture, out var ticks)
                        && ticks > 0 && ticks <= DateTime.MaxValue.Ticks
            ? DateTime.UtcNow - new DateTime(ticks, DateTimeKind.Utc)
            : null;
        int rejected;
        try
        {
            rejected = Directory.GetFiles(Path.Combine(_directory, "rejected"), "*" + SegmentExtension).Length;
        }
        catch (DirectoryNotFoundException)
        {
            rejected = 0;
        }
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero; // clock moved back
        }
        return new AgentStatusReport(bytes, segments, age, Dropped, Evicted, rejected);
    }

    /// <summary>Waits until a segment is sealed or the timeout passes.</summary>
    public Task WaitForSegmentAsync(TimeSpan timeout, CancellationToken ct) => _sealed.WaitAsync(timeout, ct);

    /// <summary>Builds the ingest request body for a segment: <c>{"events":[line,line,...]}</c>.</summary>
    public static byte[] BuildBatchJson(string segmentPath, out int count)
    {
        using var output = new MemoryStream();
        output.Write("{\"events\":["u8);
        count = 0;
        foreach (var line in File.ReadLines(segmentPath))
        {
            // A torn last line (crash mid-write) is skipped rather than poisoning the whole segment.
            if (line.Length < 2 || line[0] != '{' || line[^1] != '}')
            {
                continue;
            }
            if (count++ > 0)
            {
                output.WriteByte((byte)',');
            }
            output.Write(System.Text.Encoding.UTF8.GetBytes(line));
        }
        output.Write("]}"u8);
        return output.ToArray();
    }

    public static void Complete(string segmentPath) => File.Delete(segmentPath);

    public void Reject(string segmentPath) =>
        File.Move(segmentPath, Path.Combine(_directory, "rejected", Path.GetFileName(segmentPath)), overwrite: true);

    /// <summary>Writer loop: run once, for the agent's lifetime.</summary>
    public async Task RunWriterAsync(CancellationToken ct)
    {
        var reader = _incoming.Reader;
        while (!ct.IsCancellationRequested)
        {
            RawEnvelope first;
            try
            {
                first = await reader.ReadAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var openPath = Path.Combine(_directory, OpenFile);
            var count = 0;
            long bytes = 0;
            await using (var file = new FileStream(openPath, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024))
            {
                Write(file, first, ref count, ref bytes);
                using var age = new CancellationTokenSource(_maxAge);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, age.Token);
                try
                {
                    while (count < _maxEvents && bytes < MaxSegmentBytes && await reader.WaitToReadAsync(linked.Token))
                    {
                        while (count < _maxEvents && bytes < MaxSegmentBytes && reader.TryRead(out var next))
                        {
                            Write(file, next, ref count, ref bytes);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // Age limit reached or shutting down: seal what we have.
                }
                await file.FlushAsync(CancellationToken.None);
                file.Flush(flushToDisk: true);
            }

            Seal(openPath);
            EnforceCap();
        }
    }

    private static void Write(FileStream file, RawEnvelope envelope, ref int count, ref long bytes)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(envelope, AgentJsonContext.Default.RawEnvelope);
        file.Write(json);
        file.WriteByte((byte)'\n');
        count++;
        bytes += json.Length + 1;
    }

    private void Seal(string openPath)
    {
        // Ticks keep names sortable; the counter breaks ties within one tick.
        var name = $"{DateTime.UtcNow.Ticks.ToString("D20", CultureInfo.InvariantCulture)}-{Interlocked.Increment(ref _sequence).ToString("D6", CultureInfo.InvariantCulture)}{SegmentExtension}";
        File.Move(openPath, Path.Combine(_directory, name));
        _sealed.Release();
    }

    private long _sequence;

    private void RecoverOpenSegment()
    {
        var openPath = Path.Combine(_directory, OpenFile);
        if (File.Exists(openPath) && new FileInfo(openPath).Length > 0)
        {
            Seal(openPath);
        }
    }

    private void EnforceCap()
    {
        var segments = SealedSegments().Select(p => new FileInfo(p)).ToList();
        var total = segments.Sum(f => f.Length);
        foreach (var oldest in segments)
        {
            if (total <= _maxBytes)
            {
                break;
            }
            Interlocked.Add(ref _evicted, File.ReadLines(oldest.FullName).LongCount());
            total -= oldest.Length;
            oldest.Delete();
        }
    }

    public void Dispose() => _sealed.Dispose();
}
