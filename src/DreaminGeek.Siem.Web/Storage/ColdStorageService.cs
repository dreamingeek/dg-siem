using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Web.Storage;

public enum ColdStorageMode
{
    /// <summary>No bucket yet.</summary>
    NotSetUp,

    /// <summary>The bucket is saved here and the server writes ClickHouse's config for it.</summary>
    ManagedHere,

    /// <summary>ClickHouse has the cold tier from a config file the server didn't write (docker-compose.s3.yml).</summary>
    SetUpOutside,
}

/// <param name="ConfigWritable">Whether the server can write ClickHouse's config folder (docker-compose.yml shares it).</param>
/// <param name="ColdParts">Parts already in the bucket: once there are any, the bucket can't change.</param>
public sealed record ColdStorageStatus(ColdStorageMode Mode, string? Endpoint, string? AccessKeyId, bool DiskLoaded, long ColdParts, bool ConfigWritable);

/// <summary>
/// The cold tier's bucket, set up in the UI: saved in PostgreSQL (secret encrypted), written as a config file into the
/// folder ClickHouse reads as conf.d, and applied with <c>SYSTEM RELOAD CONFIG</c>, no restart needed. ClickHouse
/// picks up new disks and changed keys on reload, but not a changed endpoint for a disk it already has; so once
/// the bucket is in use only the keys can change.
/// </summary>
public sealed partial class ColdStorageService(
    SettingsStore settings, ClickHouseStorage storage, IOptions<ClickHouseOptions> options, ILogger<ColdStorageService> logger)
{
    public const string FileName = "dg-siem-cold-storage.xml";

    private string ConfigPath => Path.Combine(options.Value.ConfigDirectory, FileName);

    public async Task<ColdStorageStatus> GetStatusAsync(CancellationToken ct)
    {
        var saved = await settings.GetColdStorageAsync(ct);
        var (loaded, parts) = await storage.GetColdDiskAsync(ct);
        var mode = saved is not null ? ColdStorageMode.ManagedHere : loaded ? ColdStorageMode.SetUpOutside : ColdStorageMode.NotSetUp;
        return new ColdStorageStatus(mode, saved?.Endpoint, saved?.AccessKeyId, loaded, parts, CanWriteConfig());
    }

    /// <summary>
    /// At startup: rewrites ClickHouse's config file from the saved settings if it's missing or different (a recreated
    /// volume, a restored backup), and reloads. Returns a problem to show, or null.
    /// </summary>
    public async Task<string?> EnsureAsync(CancellationToken ct)
    {
        var saved = await settings.GetColdStorageAsync(ct);
        if (saved is null)
        {
            return null;
        }
        var wanted = ClickHouseStorage.ColdStorageConfig(Bucket(saved), options.Value.DataPath);
        try
        {
            if (File.Exists(ConfigPath) && await File.ReadAllTextAsync(ConfigPath, ct) == wanted)
            {
                return null;
            }
            await WriteConfigAsync(wanted, ct);
            await storage.ReloadConfigAsync(ct);
            LogRewritten(logger, ConfigPath);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"Couldn't write ClickHouse's cold storage config to {options.Value.ConfigDirectory}: {ex.Message}. Update docker-compose.yml (see docs/storage.md).";
        }
    }

    /// <summary>
    /// Tests the bucket from ClickHouse, then saves it and applies it. <paramref name="secret"/> null keeps the saved
    /// secret (to change only the key ID, or re-save). Throws <see cref="AdminException"/> with what to fix.
    /// </summary>
    public async Task SaveAsync(string endpoint, string accessKeyId, string? secret, CancellationToken ct)
    {
        var saved = await settings.GetColdStorageAsync(ct);
        var bucket = new ColdBucket(
            NormalizeEndpoint(endpoint),
            accessKeyId?.Trim() is { Length: > 0 } id ? id : throw new AdminException("Enter the access key ID."),
            string.IsNullOrWhiteSpace(secret) ? saved?.SecretAccessKey ?? throw new AdminException("Enter the secret access key.") : secret.Trim());

        var (loaded, parts) = await storage.GetColdDiskAsync(ct);
        if (saved is not null && loaded && !string.Equals(saved.Endpoint, bucket.Endpoint, StringComparison.Ordinal))
        {
            throw new AdminException(
                "ClickHouse is already using the saved bucket, and it only switches buckets on a restart, which would strand the events " +
                "already there. Only the keys can change here; see docs/storage.md to move to another bucket.");
        }
        if (!CanWriteConfig())
        {
            throw new AdminException(
                $"The server can't write ClickHouse's config folder ({options.Value.ConfigDirectory}). Update docker-compose.yml from the repo and run " +
                "docker compose up -d; see docs/storage.md.");
        }
        if (await storage.TestBucketAsync(bucket, ct) is { } error)
        {
            throw new AdminException($"ClickHouse couldn't use the bucket: {FirstLine(error)}");
        }
        if (parts > 0 && await storage.CountBucketObjectsAsync(bucket, ct) == 0)
        {
            // Set up outside the UI (docker-compose.s3.yml) with events already moved: insist on the same folder.
            throw new AdminException(
                "Events are already in cold storage, but that bucket folder is empty. Enter the bucket and folder ClickHouse uses now " +
                "(DGSIEM_S3_ENDPOINT in .env).");
        }

        await settings.SaveColdStorageAsync(new ColdStorageSettings(bucket.Endpoint, bucket.AccessKeyId, bucket.SecretAccessKey), ct);
        await WriteConfigAsync(ClickHouseStorage.ColdStorageConfig(bucket, options.Value.DataPath), ct);
        try
        {
            await storage.ReloadConfigAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new AdminException($"Saved, but ClickHouse refused the config: {FirstLine(ex.Message)}");
        }
        if (!(await storage.GetStatusAsync(ct)).TieredPolicyAvailable)
        {
            throw new AdminException("Saved, but ClickHouse didn't load the cold storage policy. Check that docker-compose.yml mounts the config folder as conf.d.");
        }
        LogSaved(logger, bucket.Endpoint);
    }

    /// <summary>
    /// The bucket URL with a folder, ending in <c>/</c>: <c>https://s3.us-west-004.backblazeb2.com/my-bucket/dg-siem/</c>.
    /// </summary>
    public static string NormalizeEndpoint(string endpoint)
    {
        var text = endpoint?.Trim() ?? string.Empty;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || uri.Query.Length > 0 || uri.Fragment.Length > 0)
        {
            throw new AdminException("Enter the bucket as a URL, e.g. https://s3.us-west-004.backblazeb2.com/my-bucket/dg-siem/.");
        }
        if (uri.AbsolutePath.Trim('/').Length == 0 && !uri.Host.Contains(".s3.", StringComparison.OrdinalIgnoreCase))
        {
            throw new AdminException("Add the bucket name (and a folder) to the URL, e.g. https://s3.us-west-004.backblazeb2.com/my-bucket/dg-siem/.");
        }
        return text.EndsWith('/') ? text : text + "/";
    }

    private async Task WriteConfigAsync(string content, CancellationToken ct)
    {
        Directory.CreateDirectory(options.Value.ConfigDirectory);
        var temp = ConfigPath + ".tmp";
        await File.WriteAllTextAsync(temp, content, ct);
        if (!OperatingSystem.IsWindows())
        {
            // Holds the bucket secret: readable by ClickHouse through the folder's group only.
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }
        File.Move(temp, ConfigPath, overwrite: true);
    }

    private bool CanWriteConfig()
    {
        try
        {
            if (!Directory.Exists(options.Value.ConfigDirectory))
            {
                return false;
            }
            var probe = Path.Combine(options.Value.ConfigDirectory, $".write-test-{Guid.NewGuid():N}");
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static ColdBucket Bucket(ColdStorageSettings s) => new(s.Endpoint, s.AccessKeyId, s.SecretAccessKey ?? string.Empty);

    private static string FirstLine(string text)
    {
        var line = text.Split('\n', 2)[0].Trim();
        return line.Length > 400 ? line[..400] + "…" : line;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Cold storage bucket saved and applied: {Endpoint}")]
    private static partial void LogSaved(ILogger logger, string endpoint);

    [LoggerMessage(Level = LogLevel.Information, Message = "Rewrote ClickHouse's cold storage config at {Path}")]
    private static partial void LogRewritten(ILogger logger, string path);
}
