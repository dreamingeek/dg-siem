using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>
/// Tails log files. Each line (or multi-line event) is wrapped in an RFC 5424 header (this host, the app name)
/// so the server's parsers treat it like forwarded syslog; the file path travels as <c>log.file.path</c>.
/// <list type="bullet">
/// <item>Rotation by rename (logrotate default) and by copy-truncate are both handled: the old file is read to
/// its end before the new one starts.</item>
/// <item>A file is identified by a hash of its first bytes, not its name, so a new file at the same path is
/// read from the start.</item>
/// <item>Positions are saved every few seconds and on shutdown; a restart resumes where it left off.</item>
/// </list>
/// </summary>
public sealed partial class FileTailInput(InputConfig config, DiskBuffer buffer, FilePositions positions, ILogger logger)
{
    internal const int FingerprintBytes = 256;
    internal const int MaxLineBytes = 64 * 1024;
    private const int MaxFiles = 512;
    private const int ReadChunk = 256 * 1024;
    private static readonly TimeSpan Poll = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MultilineIdle = TimeSpan.FromSeconds(2);

    private readonly Dictionary<string, Tracked> _files = new(StringComparer.Ordinal);
    private readonly string _host = Environment.MachineName;
    private bool _initialScan = true;

    /// <summary>For tests: called instead of the buffer when set.</summary>
    internal Action<RawEnvelope>? Emit { get; init; }

    /// <summary>For tests: the clock.</summary>
    internal Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;

    public async Task RunAsync(CancellationToken ct)
    {
        var patterns = string.Join(", ", config.Paths ?? []);
        LogTailing(logger, patterns);
        var saveEvery = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                PollOnce();
                if (++saveEvery % 5 == 0)
                {
                    positions.Save();
                }
                await Task.Delay(Poll, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Stopping.
        }
        finally
        {
            foreach (var file in _files.Values)
            {
                FlushPending(file);
                file.Dispose();
            }
            _files.Clear();
            positions.Save();
        }
    }

    /// <summary>One pass: find files, notice rotation, read new lines.</summary>
    internal void PollOnce()
    {
        var present = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in Expand(config.Paths ?? []))
        {
            present.Add(path);
            if (!_files.ContainsKey(path) && _files.Count < MaxFiles)
            {
                TryStart(path);
            }
        }
        _initialScan = false;

        foreach (var (path, file) in _files.ToList())
        {
            try
            {
                if (!present.Contains(path) || !File.Exists(path))
                {
                    // Deleted or renamed away: finish what was written, then let go.
                    ReadNew(file);
                    FlushPending(file);
                    file.Dispose();
                    _files.Remove(path);
                    positions.Remove(path);
                    continue;
                }

                var length = new FileInfo(path).Length;
                var (fingerprint, fingerprintLength) = Fingerprint(path, file.FingerprintLength);
                if (fingerprint != file.Fingerprint || length < file.Position)
                {
                    // Rotated (a new file took the name) or truncated: drain the old handle, then start over.
                    ReadNew(file);
                    FlushPending(file);
                    file.Dispose();
                    _files.Remove(path);
                    if (Open(path, 0) is { } next)
                    {
                        _files[path] = next;
                        LogRotated(logger, path);
                        ReadNew(next);
                        positions.Set(path, new FilePosition { Fingerprint = next.Fingerprint, FingerprintLength = next.FingerprintLength, Offset = next.Position });
                    }
                    continue;
                }
                // The first bytes of a small file grow into a longer fingerprint as it fills.
                if (fingerprintLength > file.FingerprintLength && file.Position >= fingerprintLength)
                {
                    (file.Fingerprint, file.FingerprintLength) = Fingerprint(path, FingerprintBytes);
                }

                ReadNew(file);
                if (file.Pending is not null && Now() - file.LastData > MultilineIdle)
                {
                    FlushPending(file);
                }
                positions.Set(path, new FilePosition { Fingerprint = file.Fingerprint, FingerprintLength = file.FingerprintLength, Offset = file.Position });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                LogReadFailed(logger, path, ex.Message);
            }
        }
    }

    private void TryStart(string path)
    {
        try
        {
            var length = new FileInfo(path).Length;
            long start;
            if (positions.Get(path) is { } saved && saved.Offset <= length
                && Fingerprint(path, saved.FingerprintLength).Hash == saved.Fingerprint)
            {
                start = saved.Offset; // same file as before the restart
            }
            else
            {
                // Files already there when the input starts begin at their end (unless asked otherwise);
                // files that appear later (e.g. after rotation) are read from the start.
                start = _initialScan && !config.FromBeginning ? length : 0;
            }
            if (Open(path, start) is { } file)
            {
                _files[path] = file;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            LogReadFailed(logger, path, ex.Message);
        }
    }

    private static Tracked? Open(string path, long position)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
        var (fingerprint, length) = Fingerprint(stream, FingerprintBytes);
        stream.Position = Math.Min(position, stream.Length);
        return new Tracked(path, stream) { Position = stream.Position, Fingerprint = fingerprint, FingerprintLength = length };
    }

    /// <summary>Reads everything appended since the last pass and emits complete lines.</summary>
    private void ReadNew(Tracked file)
    {
        var chunk = new byte[ReadChunk];
        file.Stream.Position = file.Position;
        int read;
        while ((read = file.Stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            file.Position += read;
            file.LastData = Now();
            var start = 0;
            for (var i = 0; i < read; i++)
            {
                if (chunk[i] != (byte)'\n')
                {
                    continue;
                }
                Append(file, chunk.AsSpan(start, i - start));
                Line(file, Encoding.UTF8.GetString(file.Partial.GetBuffer(), 0, (int)file.Partial.Length).TrimEnd('\r'));
                file.Partial.SetLength(0);
                file.Overlong = false;
                start = i + 1;
            }
            Append(file, chunk.AsSpan(start, read - start));
        }
    }

    /// <summary>Holds a partial line; anything past <see cref="MaxLineBytes"/> is dropped.</summary>
    private static void Append(Tracked file, ReadOnlySpan<byte> bytes)
    {
        var room = MaxLineBytes - (int)file.Partial.Length;
        if (room <= 0)
        {
            file.Overlong = true;
            return;
        }
        file.Partial.Write(bytes.Length > room ? bytes[..room] : bytes);
    }

    private void Line(Tracked file, string line)
    {
        if (config.Multiline is MultilineMode.Indented or MultilineMode.Pattern)
        {
            var continues = config.Multiline == MultilineMode.Indented
                ? line.Length > 0 && line[0] is ' ' or '\t'
                : !StartsEvent(line);
            if (continues && file.Pending is not null)
            {
                if (file.Pending.Length < MaxLineBytes)
                {
                    file.Pending.Append('\n').Append(line);
                }
                return;
            }
            FlushPending(file);
            file.Pending = new StringBuilder(line);
            return;
        }
        Send(file.Path, line);
    }

    private void FlushPending(Tracked file)
    {
        if (file.Pending is { } pending)
        {
            file.Pending = null;
            Send(file.Path, pending.ToString().TrimEnd('\n', '\r', ' ', '\t'));
        }
    }

    private Regex? _start;

    /// <summary><see cref="MultilineMode.Pattern"/>: does this line begin a new event? A bad or slow pattern counts as yes.</summary>
    private bool StartsEvent(string line)
    {
        try
        {
            _start ??= new Regex(config.MultilineStart ?? "^\\S", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            return _start.IsMatch(line);
        }
        catch (Exception ex) when (ex is ArgumentException or RegexMatchTimeoutException)
        {
            return true;
        }
    }

    private void Send(string path, string line)
    {
        if (line.Length == 0)
        {
            return;
        }
        var envelope = new RawEnvelope(Now(), $"file:{path}", null, Wrap(line, path), config.Dataset);
        if (Emit is { } emit)
        {
            emit(envelope);
        }
        else
        {
            buffer.TryEnqueue(envelope);
        }
    }

    /// <summary>
    /// <c>&lt;14&gt;1 TIME HOST APP - - - LINE</c>: user.info, as forwarded syslog would look. The time carries this
    /// host's UTC offset, so the server can place local timestamps inside the line (Asterisk, Apache) exactly.
    /// </summary>
    internal string Wrap(string line, string path) =>
        string.Create(CultureInfo.InvariantCulture,
            $"<14>1 {TimeZoneInfo.ConvertTime(Now(), Zone):yyyy-MM-ddTHH:mm:ss.ffffffzzz} {Token(_host)} {Token(config.App ?? Path.GetFileNameWithoutExtension(path))} - - - {line}");

    /// <summary>For tests; the machine's zone otherwise.</summary>
    internal TimeZoneInfo Zone { get; init; } = TimeZoneInfo.Local;

    /// <summary>Syslog header fields can't contain spaces and are at most 48 printable ASCII characters.</summary>
    internal static string Token(string? value)
    {
        var text = new string((value ?? string.Empty).Select(c => c is > ' ' and < (char)127 ? c : '_').ToArray());
        return text.Length == 0 ? "-" : text.Length > 48 ? text[..48] : text;
    }

    /// <summary>Paths with <c>*</c>/<c>?</c> in the file name expand to the matching files, sorted.</summary>
    internal static IEnumerable<string> Expand(IEnumerable<string> patterns)
    {
        foreach (var pattern in patterns)
        {
            var directory = Path.GetDirectoryName(pattern);
            var name = Path.GetFileName(pattern);
            if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(name) || !Directory.Exists(directory))
            {
                continue;
            }
            if (name.IndexOfAny(['*', '?']) < 0)
            {
                if (File.Exists(pattern))
                {
                    yield return pattern;
                }
                continue;
            }
            string[] matches;
            try
            {
                matches = Directory.GetFiles(directory, name, SearchOption.TopDirectoryOnly);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            Array.Sort(matches, StringComparer.Ordinal);
            foreach (var match in matches)
            {
                // Skip compressed rotations (app.log.1.gz) that a broad pattern can catch.
                if (!match.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) && !match.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    yield return match;
                }
            }
        }
    }

    private static (string Hash, int Length) Fingerprint(string path, int length)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Fingerprint(stream, length);
    }

    private static (string Hash, int Length) Fingerprint(FileStream stream, int length)
    {
        var position = stream.Position;
        stream.Position = 0;
        var bytes = new byte[Math.Min(length, FingerprintBytes)];
        var total = 0;
        int read;
        while (total < bytes.Length && (read = stream.Read(bytes, total, bytes.Length - total)) > 0)
        {
            total += read;
        }
        stream.Position = position;
        return (Convert.ToHexString(SHA256.HashData(bytes.AsSpan(0, total)))[..32], total);
    }

    private sealed class Tracked(string path, FileStream stream) : IDisposable
    {
        public string Path { get; } = path;
        public FileStream Stream { get; } = stream;
        public long Position { get; set; }
        public string Fingerprint { get; set; } = string.Empty;
        public int FingerprintLength { get; set; }
        public MemoryStream Partial { get; } = new();
        public bool Overlong { get; set; }
        public StringBuilder? Pending { get; set; }
        public DateTimeOffset LastData { get; set; }

        public void Dispose()
        {
            Stream.Dispose();
            Partial.Dispose();
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Tailing {Paths}")]
    private static partial void LogTailing(ILogger logger, string paths);

    [LoggerMessage(Level = LogLevel.Information, Message = "{Path} was rotated; reading the new file")]
    private static partial void LogRotated(ILogger logger, string path);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Can't read {Path}: {Reason}")]
    private static partial void LogReadFailed(ILogger logger, string path, string reason);
}

/// <summary>Saved read positions for every tailed file (<c>file-positions.json</c> in the agent's data folder).</summary>
public sealed class FilePositions(string path)
{
    private readonly Lock _gate = new();
    private Dictionary<string, FilePosition>? _positions;
    private bool _dirty;

    public FilePosition? Get(string file)
    {
        lock (_gate)
        {
            return Load().GetValueOrDefault(file);
        }
    }

    public void Set(string file, FilePosition position)
    {
        lock (_gate)
        {
            var all = Load();
            if (!all.TryGetValue(file, out var old) || old.Offset != position.Offset || old.Fingerprint != position.Fingerprint)
            {
                all[file] = position;
                _dirty = true;
            }
        }
    }

    public void Remove(string file)
    {
        lock (_gate)
        {
            _dirty |= Load().Remove(file);
        }
    }

    public void Save()
    {
        lock (_gate)
        {
            if (!_dirty || _positions is null)
            {
                return;
            }
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_positions, AgentJsonContext.Default.DictionaryStringFilePosition));
            File.Move(temp, path, overwrite: true);
            _dirty = false;
        }
    }

    private Dictionary<string, FilePosition> Load()
    {
        if (_positions is null)
        {
            try
            {
                _positions = File.Exists(path)
                    ? JsonSerializer.Deserialize(File.ReadAllText(path), AgentJsonContext.Default.DictionaryStringFilePosition) ?? []
                    : [];
            }
            catch (JsonException)
            {
                _positions = [];
            }
        }
        return _positions;
    }
}
