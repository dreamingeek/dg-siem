using System.Diagnostics;
using System.Runtime.Versioning;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;
using Microsoft.Extensions.Logging;

namespace DreaminGeek.Siem.Tests;

/// <summary>
/// Reads real event logs, so these only do anything on Windows (CI runs them on a Windows runner as
/// Administrator, which eventcreate and the Security log need). On Linux they return immediately.
/// </summary>
[Trait("Category", "Windows")]
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogInputTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("dgsiem-evt-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public async Task Reads_new_events_and_resumes_after_its_bookmark()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var config = new InputConfig
        {
            Type = InputType.WindowsEventLog,
            Channels = [new EventLogChannel { Name = "Application", Query = "*[System[Provider[@Name='DGSiemTest']]]" }],
        };
        var bookmarks = Path.Combine(_dir, "bookmarks.json");
        var first = $"dgsiem-test-{Guid.NewGuid():N}";
        var second = $"dgsiem-test-{Guid.NewGuid():N}";

        var sent = await RunUntil(config, bookmarks, first, () => Write(first));
        var xml = Assert.Single(sent, m => m.Message.Contains(first, StringComparison.Ordinal)).Message;
        Assert.StartsWith("<Event", xml, StringComparison.Ordinal);
        Assert.Contains("<RenderingInfo", xml, StringComparison.Ordinal);
        Assert.Equal("wineventlog:Application", sent[0].Input);
        Assert.Contains("Application", File.ReadAllText(bookmarks), StringComparison.Ordinal);

        // Written while the input was stopped: read on restart, and the first event isn't read again.
        Write(second);
        var resumed = await RunUntil(config, bookmarks, second, () => { });
        Assert.Contains(resumed, m => m.Message.Contains(second, StringComparison.Ordinal));
        Assert.DoesNotContain(resumed, m => m.Message.Contains(first, StringComparison.Ordinal));

        // And the server makes sense of it.
        var e = new ParserRegistry([new WindowsEventParser()]).Parse(resumed.Single(m => m.Message.Contains(second, StringComparison.Ordinal)), "dg");
        Assert.Equal("windows.application", e.EventDataset);
        Assert.Equal("101", e.Fields["event.code"]);
        Assert.Contains(second, e.Message, StringComparison.Ordinal);
        Assert.Equal(Environment.MachineName, e.HostName.Split('.')[0], ignoreCase: true);
    }

    [Fact]
    public async Task Default_queries_are_accepted_by_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var security = EventLogChannel.Defaults().Single(c => c.Name == "Security");
        var config = new InputConfig { Type = InputType.WindowsEventLog, FromBeginning = true, Channels = [security] };
        var logger = new ListLogger();
        var sent = new List<RawEnvelope>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var input = new WindowsEventLogInput(config, null!, new EventLogBookmarks(Path.Combine(_dir, "b.json")), logger)
        {
            Emit = e => { lock (sent) { sent.Add(e); if (sent.Count >= 5) { cts.Cancel(); } } return true; },
        };
        await input.RunAsync(cts.Token);
        Assert.DoesNotContain(logger.Messages, m => m.Contains("can't be read", StringComparison.Ordinal));
        Assert.NotEmpty(sent);
        var parsed = new ParserRegistry([new WindowsEventParser()]).Parse(sent[0], "dg");
        Assert.Equal("windows.security", parsed.EventDataset);
    }

    private static async Task<List<RawEnvelope>> RunUntil(InputConfig config, string bookmarks, string marker, Action afterStart)
    {
        var sent = new List<RawEnvelope>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var input = new WindowsEventLogInput(config, null!, new EventLogBookmarks(bookmarks), new ListLogger())
        {
            Emit = e =>
            {
                lock (sent)
                {
                    sent.Add(e);
                    if (e.Message.Contains(marker, StringComparison.Ordinal))
                    {
                        // Give the bookmark a moment to be recorded, then stop.
                        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
                    }
                }
                return true;
            },
        };
        var run = input.RunAsync(cts.Token);
        await Task.Delay(TimeSpan.FromSeconds(2)); // subscription in place
        afterStart();
        await run;
        Assert.True(sent.Exists(m => m.Message.Contains(marker, StringComparison.Ordinal)), $"Event {marker} wasn't read within 30s.");
        return sent;
    }

    private static void Write(string text)
    {
        using var p = Process.Start(new ProcessStartInfo("eventcreate.exe", $"/L APPLICATION /T INFORMATION /SO DGSiemTest /ID 101 /D \"{text}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
    }

    private sealed class ListLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Messages)
            {
                Messages.Add(formatter(state, exception));
            }
        }
    }
}
