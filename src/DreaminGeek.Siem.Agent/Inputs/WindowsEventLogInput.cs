using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>
/// Reads Windows event logs through the Event Log API (wevtapi.dll) with a pull subscription per channel.
/// Each event is rendered as XML including <c>RenderingInfo</c> (the message text, level and task names, the
/// same thing Windows Event Forwarding sends) and buffered as input <c>wineventlog:&lt;channel&gt;</c>; the
/// server parses it. A bookmark per channel (in <c>eventlog-bookmarks.json</c>) makes restarts resume exactly
/// where they stopped. Logs that don't exist (Sysmon not installed) are retried every few minutes.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsEventLogInput(InputConfig config, DiskBuffer buffer, EventLogBookmarks bookmarks, ILogger logger)
{
    private static readonly TimeSpan MissingChannelRetry = TimeSpan.FromMinutes(5);
    private const int BatchSize = 64;

    /// <summary>For tests: called instead of the buffer when set.</summary>
    internal Func<RawEnvelope, bool>? Emit { get; init; }

    public Task RunAsync(CancellationToken ct)
    {
        var channels = config.Channels is { Count: > 0 } list ? list : EventLogChannel.Defaults();
        // One thread per channel: the API blocks, and each channel keeps its own position.
        var tasks = channels.Select(c => Task.Factory.StartNew(() => RunChannel(c, ct), ct, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        return Task.WhenAll(tasks);
    }

    private void RunChannel(EventLogChannel channel, CancellationToken ct)
    {
        var reported = false;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ReadChannel(channel, ct);
                return;
            }
            catch (EventLogUnavailableException ex)
            {
                if (!reported)
                {
                    LogUnavailable(logger, channel.Name, ex.Message);
                    reported = true;
                }
            }
            catch (Win32Exception ex)
            {
                LogFailed(logger, channel.Name, ex.Message);
            }
            ct.WaitHandle.WaitOne(MissingChannelRetry);
        }
    }

    private void ReadChannel(EventLogChannel channel, CancellationToken ct)
    {
        using var signal = new EventWaitHandle(false, EventResetMode.AutoReset);
        var saved = bookmarks.Get(channel.Name);
        var bookmark = WevtApi.EvtCreateBookmark(saved);
        if (bookmark == 0)
        {
            bookmark = WevtApi.EvtCreateBookmark(null); // a stale or corrupt bookmark: start over
            saved = null;
        }
        nint subscription = 0;
        var publishers = new Dictionary<string, nint>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var flags = saved is not null ? WevtApi.SubscribeStartAfterBookmark
                : config.FromBeginning ? WevtApi.SubscribeStartAtOldestRecord
                : WevtApi.SubscribeToFutureEvents;
            subscription = WevtApi.EvtSubscribe(0, signal.SafeWaitHandle.DangerousGetHandle(), channel.Name,
                string.IsNullOrWhiteSpace(channel.Query) ? "*" : channel.Query, saved is null ? 0 : bookmark, 0, 0, flags);
            if (subscription == 0)
            {
                var error = Marshal.GetLastPInvokeError();
                throw error is WevtApi.ErrorChannelNotFound or WevtApi.ErrorAccessDenied or WevtApi.ErrorInvalidQuery
                    ? new EventLogUnavailableException(new Win32Exception(error).Message + (error == WevtApi.ErrorInvalidQuery ? $" (query: {channel.Query})" : ""))
                    : new Win32Exception(error);
            }
            LogReading(logger, channel.Name);

            var handles = new nint[BatchSize];
            var waits = new[] { signal, ct.WaitHandle };
            while (!ct.IsCancellationRequested)
            {
                if (!WevtApi.EvtNext(subscription, BatchSize, handles, 0, 0, out var returned))
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (error is not (WevtApi.ErrorNoMoreItems or WevtApi.ErrorTimeout or WevtApi.ErrorInvalidOperation))
                    {
                        throw new Win32Exception(error);
                    }
                    WaitHandle.WaitAny(waits, TimeSpan.FromSeconds(5));
                    continue;
                }
                try
                {
                    for (var i = 0; i < returned && !ct.IsCancellationRequested; i++)
                    {
                        var xml = Render(handles[i], publishers);
                        if (xml is null)
                        {
                            continue;
                        }
                        var envelope = new RawEnvelope(DateTimeOffset.UtcNow, $"wineventlog:{channel.Name}", null, xml, config.Dataset);
                        // A full buffer (server unreachable for days): hold here rather than skip events.
                        while (!(Emit?.Invoke(envelope) ?? buffer.TryEnqueue(envelope)) && !ct.IsCancellationRequested)
                        {
                            ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(1));
                        }
                        WevtApi.EvtUpdateBookmark(bookmark, handles[i]);
                    }
                }
                finally
                {
                    for (var i = 0; i < returned; i++)
                    {
                        WevtApi.EvtClose(handles[i]);
                    }
                }
                if (WevtApi.RenderString(bookmark, WevtApi.RenderBookmark) is { } position)
                {
                    bookmarks.Set(channel.Name, position);
                }
            }
        }
        finally
        {
            bookmarks.Flush();
            if (subscription != 0)
            {
                WevtApi.EvtClose(subscription);
            }
            WevtApi.EvtClose(bookmark);
            foreach (var handle in publishers.Values.Where(h => h != 0))
            {
                WevtApi.EvtClose(handle);
            }
        }
    }

    [GeneratedRegex(@"<Provider Name=['""](?<name>[^'""]+)['""]", RegexOptions.CultureInvariant)]
    private static partial Regex ProviderRegex();

    /// <summary>The event as XML with its message text, or the bare event XML when the provider's messages aren't installed.</summary>
    private static string? Render(nint evt, Dictionary<string, nint> publishers)
    {
        var xml = WevtApi.RenderString(evt, WevtApi.RenderEventXml);
        if (xml is null)
        {
            return null;
        }
        if (ProviderRegex().Match(xml) is { Success: true } m)
        {
            var provider = m.Groups["name"].Value;
            if (!publishers.TryGetValue(provider, out var metadata))
            {
                metadata = WevtApi.EvtOpenPublisherMetadata(0, provider, null, 0, 0);
                publishers[provider] = metadata; // 0 = no metadata; don't try again for this provider
            }
            if (metadata != 0 && WevtApi.FormatXml(metadata, evt) is { } full)
            {
                return full;
            }
        }
        return xml;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Reading event log {Channel}")]
    private static partial void LogReading(ILogger logger, string channel);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Event log {Channel} can't be read: {Reason}. Retrying every 5 minutes.")]
    private static partial void LogUnavailable(ILogger logger, string channel, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Event log {Channel} failed: {Reason}. Restarting in 5 minutes.")]
    private static partial void LogFailed(ILogger logger, string channel, string reason);
}

internal sealed class EventLogUnavailableException(string message) : Exception(message);

/// <summary>Where each event log got to (bookmark XML per channel), saved at most every few seconds.</summary>
public sealed class EventLogBookmarks(string path)
{
    private readonly Lock _lock = new();
    private Dictionary<string, string>? _bookmarks;
    private bool _dirty;
    private DateTime _lastSave = DateTime.MinValue;

    public string? Get(string channel)
    {
        lock (_lock)
        {
            return Load().GetValueOrDefault(channel);
        }
    }

    public void Set(string channel, string bookmarkXml)
    {
        lock (_lock)
        {
            Load()[channel] = bookmarkXml;
            _dirty = true;
            if (DateTime.UtcNow - _lastSave > TimeSpan.FromSeconds(5))
            {
                Save();
            }
        }
    }

    public void Flush()
    {
        lock (_lock)
        {
            if (_dirty)
            {
                Save();
            }
        }
    }

    private Dictionary<string, string> Load()
    {
        if (_bookmarks is null)
        {
            try
            {
                _bookmarks = File.Exists(path)
                    ? JsonSerializer.Deserialize(File.ReadAllText(path), AgentJsonContext.Default.DictionaryStringString) ?? []
                    : [];
            }
            catch (JsonException)
            {
                _bookmarks = [];
            }
            _bookmarks = new Dictionary<string, string>(_bookmarks, StringComparer.OrdinalIgnoreCase);
        }
        return _bookmarks;
    }

    private void Save()
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(Load(), AgentJsonContext.Default.DictionaryStringString));
        File.Move(tmp, path, overwrite: true);
        _dirty = false;
        _lastSave = DateTime.UtcNow;
    }
}

/// <summary>The few wevtapi.dll calls the input needs (source-generated P/Invoke: AOT-safe).</summary>
[SupportedOSPlatform("windows")]
internal static partial class WevtApi
{
    public const int SubscribeToFutureEvents = 1;
    public const int SubscribeStartAtOldestRecord = 2;
    public const int SubscribeStartAfterBookmark = 3;

    public const int RenderEventXml = 1;
    public const int RenderBookmark = 2;
    private const int FormatMessageXml = 9;

    public const int ErrorAccessDenied = 5;
    public const int ErrorInsufficientBuffer = 122;
    public const int ErrorNoMoreItems = 259;
    public const int ErrorTimeout = 1460;
    public const int ErrorInvalidOperation = 4317;
    public const int ErrorInvalidQuery = 15001;
    public const int ErrorChannelNotFound = 15007;

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial nint EvtSubscribe(nint session, nint signalEvent, string channelPath, string? query, nint bookmark, nint context, nint callback, int flags);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool EvtNext(nint resultSet, int eventsSize, [Out] nint[] events, int timeout, int flags, out int returned);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool EvtClose(nint handle);

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial nint EvtCreateBookmark(string? bookmarkXml);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool EvtUpdateBookmark(nint bookmark, nint evt);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtRender(nint context, nint fragment, int flags, int bufferSize, nint buffer, out int bufferUsed, out int propertyCount);

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial nint EvtOpenPublisherMetadata(nint session, string publisherId, string? logFilePath, int locale, int flags);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtFormatMessage(nint publisherMetadata, nint evt, int messageId, int valueCount, nint values, int flags, int bufferSize, nint buffer, out int bufferUsed);

    /// <summary>EvtRender to a string (event XML or bookmark XML); null on failure.</summary>
    public static string? RenderString(nint handle, int flags)
    {
        EvtRender(0, handle, flags, 0, 0, out var needed, out _);
        if (Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer || needed <= 0)
        {
            return null;
        }
        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            return EvtRender(0, handle, flags, needed, buffer, out var used, out _)
                ? Marshal.PtrToStringUni(buffer, Math.Max(0, used / 2 - 1))
                : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>EvtFormatMessage(EvtFormatMessageXml): the event XML plus RenderingInfo; null when the message can't be formatted.</summary>
    public static string? FormatXml(nint metadata, nint evt)
    {
        EvtFormatMessage(metadata, evt, 0, 0, 0, FormatMessageXml, 0, 0, out var neededChars);
        if (Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer || neededChars <= 0)
        {
            return null;
        }
        var buffer = Marshal.AllocHGlobal(neededChars * 2);
        try
        {
            return EvtFormatMessage(metadata, evt, 0, 0, 0, FormatMessageXml, neededChars, buffer, out var used)
                ? Marshal.PtrToStringUni(buffer, Math.Max(0, used - 1))
                : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
