using System.Net;
using System.Text;
using System.Text.Json;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Tests;

public class SyslogFrameDecoderTests
{
    [Fact]
    public void Splits_newline_delimited_messages_across_reads()
    {
        var d = new SyslogFrameDecoder();
        Assert.Empty(d.Feed("<13>first par"u8));
        Assert.Equal(["<13>first part", "<13>second"], d.Feed("t\n<13>second\r\n<13>thi"u8));
        Assert.Equal("<13>thi", d.Flush());
    }

    [Fact]
    public void Handles_octet_counting_with_embedded_newlines()
    {
        var d = new SyslogFrameDecoder();
        var msg = "<13>1 - - - - - - line one\nline two";
        var frame = $"{Encoding.UTF8.GetByteCount(msg)} {msg}";
        var bytes = Encoding.UTF8.GetBytes(frame + frame);

        Assert.Empty(d.Feed(bytes.AsSpan(0, 10)));
        Assert.Equal([msg, msg], d.Feed(bytes.AsSpan(10)));
    }

    [Fact]
    public void Mixed_framing_and_nul_terminators()
    {
        var d = new SyslogFrameDecoder();
        Assert.Equal(["<13>a", "<13>b", "<13>c"], d.Feed("5 <13>a<13>b\0<13>c\n"u8));
    }

    [Fact]
    public void Oversized_messages_are_truncated_not_buffered_forever()
    {
        var d = new SyslogFrameDecoder(maxMessageBytes: 100);
        var messages = d.Feed(Encoding.ASCII.GetBytes(new string('x', 250)));
        Assert.Equal(2, messages.Count);
        Assert.All(messages, m => Assert.Equal(100, m.Length));
        Assert.Equal(2, d.Truncated);
    }
}

public class SourceHintsTests
{
    [Fact]
    public void Matches_ips_cidrs_and_ipv4_mapped_addresses()
    {
        var hints = new SourceHints(
        [
            new SourceHint { Source = "192.168.1.1", Dataset = "unifi" },
            new SourceHint { Source = "10.20.0.0/16", Dataset = "sip" },
            new SourceHint { Source = "not-an-ip", Dataset = "ignored" },
        ]);

        Assert.Equal("unifi", hints.Resolve(IPAddress.Parse("192.168.1.1"), null));
        Assert.Equal("unifi", hints.Resolve(IPAddress.Parse("192.168.1.1").MapToIPv6(), null));
        Assert.Equal("sip", hints.Resolve(IPAddress.Parse("10.20.5.9"), null));
        Assert.Equal("default", hints.Resolve(IPAddress.Parse("172.16.0.1"), "default"));
        Assert.Null(hints.Resolve(null, null));
    }
}

public sealed class DiskBufferTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "dgsiem-buffer-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Writes_seals_and_builds_ingest_batches()
    {
        using var buffer = new DiskBuffer(_dir, maxBytes: 10_000_000, maxEventsPerSegment: 3, maxSegmentAge: TimeSpan.FromMilliseconds(200));
        using var cts = new CancellationTokenSource();
        var writer = buffer.RunWriterAsync(cts.Token);

        for (var i = 0; i < 4; i++)
        {
            Assert.True(buffer.TryEnqueue(new RawEnvelope(DateTimeOffset.UtcNow, "syslog-udp", "10.0.0.1", $"<13>msg {i}", "unifi")));
        }

        // 3 events seal by count; the 4th seals by age.
        for (var tries = 0; tries < 50 && buffer.SealedSegments().Count < 2; tries++)
        {
            await Task.Delay(50);
        }
        await cts.CancelAsync();
        await writer;

        var segments = buffer.SealedSegments();
        Assert.Equal(2, segments.Count);

        var json = DiskBuffer.BuildBatchJson(segments[0], out var count);
        Assert.Equal(3, count);
        var batch = JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentIngestBatch)!;
        Assert.Equal(["<13>msg 0", "<13>msg 1", "<13>msg 2"], batch.Events.Select(e => e.Message));
        Assert.Equal("unifi", batch.Events[0].DatasetHint);

        DiskBuffer.Complete(segments[0]);
        Assert.Single(buffer.SealedSegments());
    }

    [Fact]
    public void Torn_last_line_is_skipped()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "0001.seg");
        File.WriteAllText(path, "{\"receivedAt\":\"2026-11-11T00:00:00+00:00\",\"input\":\"x\",\"sourceAddress\":null,\"message\":\"ok\",\"datasetHint\":null}\n{\"receivedAt\":\"2026-");
        DiskBuffer.BuildBatchJson(path, out var count);
        Assert.Equal(1, count);
    }

    [Fact]
    public void Leftover_open_segment_is_recovered_on_startup()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "current.open"), "{\"message\":\"x\"}\n");
        using var buffer = new DiskBuffer(_dir, 10_000_000, 100, TimeSpan.FromSeconds(1));
        Assert.Single(buffer.SealedSegments());
    }

    [Fact]
    public void Status_reports_the_backlog_and_its_age()
    {
        using var buffer = new DiskBuffer(_dir, 10_000_000, 100, TimeSpan.FromSeconds(1));
        Assert.Equal(new AgentStatusReport(0, 0, null, 0, 0, 0), buffer.Status());

        var tenMinutesAgo = DateTime.UtcNow.AddMinutes(-10).Ticks.ToString("D20", System.Globalization.CultureInfo.InvariantCulture);
        var now = DateTime.UtcNow.Ticks.ToString("D20", System.Globalization.CultureInfo.InvariantCulture);
        File.WriteAllText(Path.Combine(_dir, $"{tenMinutesAgo}-000001.seg"), new string('x', 100));
        File.WriteAllText(Path.Combine(_dir, $"{now}-000002.seg"), new string('x', 50));
        File.WriteAllText(Path.Combine(_dir, "rejected", "0001-000003.seg"), "bad");

        var status = buffer.Status();
        Assert.Equal(150, status.PendingBytes);
        Assert.Equal(2, status.PendingSegments);
        Assert.InRange(status.OldestPending!.Value.TotalMinutes, 9.9, 11);
        Assert.Equal(1, status.Rejected);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }
}

public sealed class AgentStatusReportTests
{
    [Fact]
    public void Round_trips_through_the_header()
    {
        var report = new AgentStatusReport(123_456_789, 42, TimeSpan.FromSeconds(605), 7, 3, 1);
        Assert.Equal(report, AgentStatusReport.Parse(report.Format()));
        var idle = new AgentStatusReport(0, 0, null, 0, 0, 0);
        Assert.Equal(idle, AgentStatusReport.Parse(idle.Format()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("dropped=5")]
    public void Missing_or_unreadable_headers_are_ignored(string? header) => Assert.Null(AgentStatusReport.Parse(header));

    [Fact]
    public void Unknown_keys_and_negative_values_are_tolerated()
    {
        var parsed = AgentStatusReport.Parse("pending-bytes=10; future-thing=99; dropped=-4; oldest-seconds=-1")!;
        Assert.Equal(10, parsed.PendingBytes);
        Assert.Equal(0, parsed.Dropped);
        Assert.Null(parsed.OldestPending);
    }
}
