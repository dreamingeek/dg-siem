using System.Globalization;
using System.Text;
using System.Text.Json;
using ClickHouse.Driver;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Web.Backups;

public sealed class BackupOptions
{
    public const string SectionName = "Backup";

    /// <summary>Where the server writes encrypted config backups (<c>${DGSIEM_BACKUP_DIR}/config</c> on the host).</summary>
    public string ConfigDirectory { get; set; } = "/backups/config";

    /// <summary>The server's view of ClickHouse's event backups (<c>${DGSIEM_BACKUP_DIR}/events</c>), for listing and pruning.</summary>
    public string EventsDirectory { get; set; } = "/backups/events";

    /// <summary>ClickHouse disk for event backups (deploy/clickhouse/backups.xml).</summary>
    public string ClickHouseDisk { get; set; } = "backups";

    /// <summary>Encrypts config backups (DGSIEM_BACKUP_PASSPHRASE). Keep a copy outside the server: without it they can't be restored.</summary>
    public string? Passphrase { get; set; }
}

/// <param name="Time">Local time (the General time zone) the nightly backup runs, <c>HH:mm</c>.</param>
/// <param name="KeepDays">Backups older than this are deleted (the newest 3 config backups are always kept).</param>
/// <param name="FullEveryDays">Event backups: a full one this often, differentials against it in between.</param>
public sealed record BackupSettings(bool Enabled = true, string Time = "03:15", int KeepDays = 30, bool IncludeEvents = true, int FullEveryDays = 7);

public sealed record EventBackup(string Name, bool Full, string? Base, DateTimeOffset At, long Bytes);

public sealed record BackupRun(
    DateTimeOffset StartedAt, DateTimeOffset? FinishedAt, bool Manual, string? ConfigFile, long ConfigBytes,
    EventBackup? Events, string? Error);

public sealed record BackupState(IReadOnlyList<BackupRun> Runs, IReadOnlyList<EventBackup> EventBackups)
{
    public static BackupState Empty { get; } = new([], []);
}

/// <summary>
/// Nightly backups to a local folder: an encrypted config archive (agent CA, key ring, PostgreSQL) written by the
/// server, and the events written by ClickHouse's BACKUP as zip archives (full every few days, differential against
/// the latest full otherwise, so a restore needs two files at most). Old backups are pruned.
/// </summary>
public sealed partial class BackupService(
    IOptions<BackupOptions> options,
    IOptions<DreaminGeek.Siem.Web.Agents.PkiOptions> pki,
    IConfiguration configuration,
    IDbContextFactory<SiemDbContext> dbFactory,
    ClickHouseClient clickHouse,
    DreaminGeek.Siem.Storage.ClickHouse.ClickHouseMigrator clickHouseMigrator,
    IOptions<DreaminGeek.Siem.Storage.ClickHouse.ClickHouseOptions> clickHouseOptions,
    SettingsStore settings,
    ILogger<BackupService> logger) : BackgroundService
{
    private const string SettingsKey = "backups";
    private const string StateKey = "backupstate";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly SemaphoreSlim _running = new(1, 1);

    public bool IsRunning => _running.CurrentCount == 0;

    public BackupOptions Options => options.Value;

    private string PostgresConnectionString =>
        new Npgsql.NpgsqlConnectionStringBuilder(configuration.GetConnectionString("Postgres")) { GssEncryptionMode = Npgsql.GssEncryptionMode.Disable }.ConnectionString;

    private string KeysDirectory => configuration.GetValue("Server:KeysDirectory", "/var/lib/dg-siem/keys")!;

    // ---- Settings and state ------------------------------------------------------------------

    public async Task<BackupSettings> GetSettingsAsync(CancellationToken ct) => await ReadAsync<BackupSettings>(SettingsKey, ct) ?? new BackupSettings();

    public Task SaveSettingsAsync(BackupSettings value, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!TimeOnly.TryParseExact(value.Time, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
        {
            throw new DreaminGeek.Siem.Web.Admin.AdminException("Time must be HH:mm, e.g. 03:15.");
        }
        if (value.KeepDays is < 1 or > 3650 || value.FullEveryDays is < 1 or > 90)
        {
            throw new DreaminGeek.Siem.Web.Admin.AdminException("Keep 1-3650 days; a full event backup every 1-90 days.");
        }
        return WriteAsync(SettingsKey, value, ct);
    }

    public async Task<BackupState> GetStateAsync(CancellationToken ct) => await ReadAsync<BackupState>(StateKey, ct) ?? BackupState.Empty;

    /// <summary>Things that stop backups working, for the Backups page.</summary>
    public async Task<IReadOnlyList<string>> CheckAsync(BackupSettings value, CancellationToken ct)
    {
        var problems = new List<string>();
        if (string.IsNullOrEmpty(Options.Passphrase) || Options.Passphrase.Length < BackupArchive.MinPassphraseLength)
        {
            problems.Add($"No backup passphrase: set DGSIEM_BACKUP_PASSPHRASE (at least {BackupArchive.MinPassphraseLength} characters) in .env and restart. Config backups are encrypted with it.");
        }
        if (!CanWrite(Options.ConfigDirectory))
        {
            problems.Add($"The server can't write to {Options.ConfigDirectory}. Update docker-compose.yml from the repo and run docker compose up -d: its dg-siem-init step sets the folder up (docs/backups.md).");
        }
        if (value.IncludeEvents)
        {
            var disk = false;
            try
            {
                using var reader = await clickHouse.ExecuteReaderAsync($"SELECT 1 FROM system.disks WHERE name = '{Options.ClickHouseDisk}'", cancellationToken: ct);
                disk = await reader.ReadAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"Couldn't ask ClickHouse about its backup disk: {ex.Message}");
            }
            if (!disk)
            {
                problems.Add("ClickHouse has no 'backups' disk, so events can't be backed up. Update docker-compose.yml (it mounts deploy/clickhouse/backups.xml) and recreate ClickHouse.");
            }
            if (!CanWrite(Options.EventsDirectory))
            {
                problems.Add($"The server can't prune old event backups in {Options.EventsDirectory}: update docker-compose.yml from the repo and run docker compose up -d (docs/backups.md).");
            }
        }
        return problems;
    }

    // ---- Schedule ----------------------------------------------------------------------------

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await ScheduleAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    private async Task ScheduleAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var config = await GetSettingsAsync(stoppingToken);
            var zone = (await settings.GetGeneralAsync(stoppingToken)).Zone;
            var next = NextRun(config, zone, DateTimeOffset.UtcNow);
            var wait = next - DateTimeOffset.UtcNow;
            // Re-read settings at least hourly, so a changed time takes effect.
            await Task.Delay(wait < TimeSpan.FromHours(1) ? wait : TimeSpan.FromHours(1), stoppingToken);
            if (DateTimeOffset.UtcNow >= next && config.Enabled)
            {
                try
                {
                    await RunAsync(manual: false, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogFailed(logger, ex.Message);
                }
            }
        }
    }

    /// <summary>The next time <paramref name="config"/>'s HH:mm comes round in <paramref name="zone"/>.</summary>
    public static DateTimeOffset NextRun(BackupSettings config, TimeZoneInfo zone, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(config);
        var time = TimeOnly.ParseExact(config.Time, "HH:mm", CultureInfo.InvariantCulture);
        var local = TimeZoneInfo.ConvertTime(now, zone);
        var candidate = new DateTime(DateOnly.FromDateTime(local.DateTime), time, DateTimeKind.Unspecified);
        for (var i = 0; i < 3; i++, candidate = candidate.AddDays(1))
        {
            if (zone.IsInvalidTime(candidate))
            {
                continue; // skipped by a DST change
            }
            var at = new DateTimeOffset(candidate, zone.GetUtcOffset(candidate));
            if (at > now)
            {
                return at;
            }
        }
        return now.AddDays(1);
    }

    // ---- Back up -----------------------------------------------------------------------------

    /// <summary>Runs a backup now. Throws <see cref="BackupException"/> if one is already running.</summary>
    public async Task<BackupRun> RunAsync(bool manual, CancellationToken ct)
    {
        if (!await _running.WaitAsync(0, ct))
        {
            throw new BackupException("A backup is already running.");
        }
        var started = DateTimeOffset.UtcNow;
        var config = await GetSettingsAsync(ct);
        var state = await GetStateAsync(ct);
        string? configFile = null;
        long configBytes = 0;
        EventBackup? events = null;
        var errors = new List<string>();
        try
        {
            try
            {
                (configFile, configBytes) = await BackUpConfigAsync(started, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add($"Config: {ex.Message}");
            }
            if (config.IncludeEvents)
            {
                try
                {
                    events = await BackUpEventsAsync(started, config, state, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    errors.Add($"Events: {ex.Message}");
                }
            }
            var eventBackups = events is null ? state.EventBackups.ToList() : [.. state.EventBackups, events];
            eventBackups = Prune(config, eventBackups, started);
            var run = new BackupRun(started, DateTimeOffset.UtcNow, manual, configFile, configBytes, events, errors.Count == 0 ? null : string.Join(" ", errors));
            await WriteAsync(StateKey, new BackupState([run, .. state.Runs.Take(59)], eventBackups), ct);
            if (run.Error is null)
            {
                LogDone(logger, configFile ?? "-", events?.Name ?? "-");
            }
            else
            {
                LogFailed(logger, run.Error);
            }
            return run;
        }
        finally
        {
            _running.Release();
        }
    }

    private async Task<(string File, long Bytes)> BackUpConfigAsync(DateTimeOffset at, CancellationToken ct)
    {
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        AddFolder(entries, "pki", pki.Value.Directory);
        AddFolder(entries, "keys", KeysDirectory);
        foreach (var (entry, data) in await PostgresDump.ExportAsync(PostgresConnectionString, ct))
        {
            entries[entry] = data;
        }
        entries["manifest.json"] = JsonSerializer.SerializeToUtf8Bytes(new
        {
            createdAt = at,
            server = typeof(BackupService).Assembly.GetName().Version?.ToString(3),
            contents = entries.Keys.Order(StringComparer.Ordinal).ToList(),
        }, Json);

        var file = BackupArchive.Write(entries, Options.Passphrase ?? string.Empty);
        Directory.CreateDirectory(Options.ConfigDirectory);
        var name = $"dg-siem-config-{at.UtcDateTime:yyyyMMdd-HHmm}.dgsb";
        var path = Path.Combine(Options.ConfigDirectory, name);
        await File.WriteAllBytesAsync(path + ".tmp", file, ct);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path + ".tmp", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }
        File.Move(path + ".tmp", path, overwrite: true);
        return (name, file.Length);
    }

    private static void AddFolder(Dictionary<string, byte[]> entries, string prefix, string folder)
    {
        if (!Directory.Exists(folder))
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly))
        {
            entries[$"{prefix}/{Path.GetFileName(file)}"] = File.ReadAllBytes(file);
        }
    }

    private async Task<EventBackup> BackUpEventsAsync(DateTimeOffset at, BackupSettings config, BackupState state, CancellationToken ct)
    {
        var lastFull = state.EventBackups.Where(b => b.Full).MaxBy(b => b.At);
        var full = lastFull is null || at - lastFull.At >= TimeSpan.FromDays(config.FullEveryDays) - TimeSpan.FromHours(2)
            || !File.Exists(Path.Combine(Options.EventsDirectory, lastFull.Name));
        var name = $"events-{at.UtcDateTime:yyyyMMdd-HHmm}-{(full ? "full" : "diff")}.zip";
        var disk = Options.ClickHouseDisk;
        var table = $"{clickHouseOptions.Value.Database}.events";
        var sql = $"BACKUP TABLE {table} TO Disk('{disk}', '{name}')" +
                  (full ? "" : $" SETTINGS base_backup = Disk('{disk}', '{lastFull!.Name}')") + " ASYNC";
        var bytes = await RunAsyncOperationAsync(sql, "BACKUP_CREATED", ct);
        // ClickHouse reports the logical size (a differential counts its base); the file is what's on disk.
        var written = new FileInfo(Path.Combine(Options.EventsDirectory, name));
        if (written.Exists)
        {
            bytes = written.Length;
        }
        return new EventBackup(name, full, full ? null : lastFull!.Name, at, bytes);
    }

    /// <summary>
    /// Runs a ClickHouse <c>BACKUP … ASYNC</c> or <c>RESTORE … ASYNC</c> and polls <c>system.backups</c> until it
    /// reaches <paramref name="done"/> (large tables take longer than an HTTP request should). Returns its size.
    /// </summary>
    private async Task<long> RunAsyncOperationAsync(string sql, string done, CancellationToken ct)
    {
        string id;
        await using (var reader = await clickHouse.ExecuteReaderAsync(sql, cancellationToken: ct))
        {
            if (!await reader.ReadAsync(ct))
            {
                throw new BackupException("ClickHouse didn't start the operation.");
            }
            id = reader.GetString(0);
        }
        var deadline = DateTimeOffset.UtcNow.AddHours(12);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
            await using var reader = await clickHouse.ExecuteReaderAsync(
                $"SELECT toString(status), toInt64(total_size), error FROM system.backups WHERE id = '{id.Replace("'", "", StringComparison.Ordinal)}'", cancellationToken: ct);
            if (!await reader.ReadAsync(ct))
            {
                continue;
            }
            var status = reader.GetString(0);
            if (status == done)
            {
                return reader.GetInt64(1);
            }
            if (status.Contains("FAILED", StringComparison.Ordinal))
            {
                throw new BackupException(FirstLine(reader.GetString(2)));
            }
        }
        throw new BackupException("ClickHouse didn't finish within 12 hours.");
    }

    /// <summary>
    /// Deletes config backups older than KeepDays (keeping the newest 3), and event backups older than KeepDays
    /// unless a kept differential still needs them as its base. Returns the event backups that remain.
    /// </summary>
    private List<EventBackup> Prune(BackupSettings config, List<EventBackup> eventBackups, DateTimeOffset now)
    {
        var cutoff = now - TimeSpan.FromDays(config.KeepDays);
        try
        {
            if (Directory.Exists(Options.ConfigDirectory))
            {
                foreach (var old in new DirectoryInfo(Options.ConfigDirectory).GetFiles("dg-siem-config-*.dgsb")
                             .OrderByDescending(f => f.Name, StringComparer.Ordinal).Skip(3).Where(f => f.LastWriteTimeUtc < cutoff.UtcDateTime))
                {
                    old.Delete();
                }
            }
        }
        catch (IOException ex)
        {
            LogPruneFailed(logger, ex.Message);
        }

        var keep = Retained(eventBackups, cutoff);
        foreach (var gone in eventBackups.Except(keep).ToList())
        {
            try
            {
                File.Delete(Path.Combine(Options.EventsDirectory, gone.Name));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                LogPruneFailed(logger, ex.Message);
                keep.Add(gone); // try again next time
            }
        }
        return keep.OrderBy(b => b.At).ToList();
    }

    /// <summary>
    /// Event backups to keep: those since <paramref name="cutoff"/>, the bases those differentials need, and always
    /// the latest full one with its differentials (so failing backups never prune the last good copy).
    /// </summary>
    public static List<EventBackup> Retained(IReadOnlyList<EventBackup> backups, DateTimeOffset cutoff)
    {
        ArgumentNullException.ThrowIfNull(backups);
        var latestFull = backups.Where(b => b.Full).MaxBy(b => b.At);
        var keep = backups.Where(b => b.At >= cutoff || b == latestFull || (latestFull is not null && b.Base == latestFull.Name)).ToList();
        var needed = keep.Where(b => b.Base is not null).Select(b => b.Base!).ToHashSet(StringComparer.Ordinal);
        keep.AddRange(backups.Where(b => !keep.Contains(b) && needed.Contains(b.Name)));
        return keep;
    }

    // ---- Restore (CLI) -----------------------------------------------------------------------

    /// <summary>
    /// <c>dg-siem-server backup restore</c>: the CA, key ring and PostgreSQL from a config backup, and optionally the
    /// events from a ClickHouse backup into an empty events table. Run with the server stopped.
    /// </summary>
    public async Task RestoreAsync(string configFile, string? eventsBackup, TextWriter output, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(output);
        var path = File.Exists(configFile) ? configFile : Path.Combine(Options.ConfigDirectory, configFile);
        var entries = BackupArchive.Read(await File.ReadAllBytesAsync(path, ct), Options.Passphrase ?? string.Empty);
        output.WriteLine($"Opened {Path.GetFileName(path)} ({entries.Count} files).");

        if (eventsBackup is not null)
        {
            // On a fresh server the events table may not exist yet. Check first, so a refused events restore
            // doesn't leave the rest half-done.
            await clickHouseMigrator.MigrateAsync(ct);
            await using var reader = await clickHouse.ExecuteReaderAsync($"SELECT count() FROM {clickHouseOptions.Value.Database}.events", cancellationToken: ct);
            if (await reader.ReadAsync(ct) && Convert.ToInt64(reader.GetValue(0), CultureInfo.InvariantCulture) > 0)
            {
                throw new BackupException("The events table isn't empty; restoring into it would duplicate events. Restore events on a fresh server.");
            }
        }

        // PostgreSQL first: it checks the schema version and is all-or-nothing.
        var counts = await PostgresDump.ImportAsync(PostgresConnectionString, entries, ct);
        output.WriteLine($"Restored PostgreSQL: {counts.Count} tables, {counts.Values.Sum()} rows.");

        foreach (var (prefix, folder) in new[] { ("pki/", pki.Value.Directory), ("keys/", KeysDirectory) })
        {
            Directory.CreateDirectory(folder);
            foreach (var (name, data) in entries.Where(e => e.Key.StartsWith(prefix, StringComparison.Ordinal)))
            {
                var file = name[prefix.Length..];
                if (file.Length > 0 && file == Path.GetFileName(file) && file is not "." and not "..")
                {
                    var target = Path.Combine(folder, file);
                    await File.WriteAllBytesAsync(target, data, ct);
                    if (!OperatingSystem.IsWindows())
                    {
                        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite); // private keys
                    }
                }
            }
            output.WriteLine($"Restored {entries.Keys.Count(k => k.StartsWith(prefix, StringComparison.Ordinal))} files to {folder}.");
        }

        if (eventsBackup is not null)
        {
            var name = Path.GetFileName(eventsBackup);
            var table = $"{clickHouseOptions.Value.Database}.events";
            output.WriteLine($"Restoring events from {name} (and its base); this can take a while...");
            await RunAsyncOperationAsync($"RESTORE TABLE {table} FROM Disk('{Options.ClickHouseDisk}', '{name.Replace("'", "", StringComparison.Ordinal)}') ASYNC", "RESTORED", ct);
            await using var reader = await clickHouse.ExecuteReaderAsync($"SELECT count() FROM {table}", cancellationToken: ct);
            await reader.ReadAsync(ct);
            output.WriteLine($"Restored {Convert.ToInt64(reader.GetValue(0), CultureInfo.InvariantCulture):N0} events.");
        }
        output.WriteLine("Done. Start the server; agents reconnect with their existing certificates.");
    }

    /// <summary>Config backups on disk, newest first.</summary>
    public IReadOnlyList<FileInfo> ListConfigBackups() =>
        Directory.Exists(Options.ConfigDirectory)
            ? new DirectoryInfo(Options.ConfigDirectory).GetFiles("dg-siem-config-*.dgsb").OrderByDescending(f => f.Name, StringComparer.Ordinal).ToList()
            : [];

    // ---- Helpers -----------------------------------------------------------------------------

    private static bool CanWrite(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            var probe = Path.Combine(folder, $".write-test-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string FirstLine(string text) => text.Split('\n', 2)[0].Trim();

    private async Task<T?> ReadAsync<T>(string key, CancellationToken ct) where T : class
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var row = await db.AppSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Key == key, ct);
        return row is null ? null : JsonSerializer.Deserialize<T>(row.Value, Json);
    }

    private async Task WriteAsync<T>(string key, T value, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var json = JsonSerializer.Serialize(value, Json);
        var row = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (row is null)
        {
            db.AppSettings.Add(new AppSetting { Key = key, Value = json });
        }
        else
        {
            row.Value = json;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Backup done: {ConfigFile}, {EventsFile}")]
    private static partial void LogDone(ILogger logger, string configFile, string eventsFile);

    [LoggerMessage(Level = LogLevel.Error, Message = "Backup failed: {Reason}")]
    private static partial void LogFailed(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Couldn't delete an old backup: {Reason}")]
    private static partial void LogPruneFailed(ILogger logger, string reason);
}
