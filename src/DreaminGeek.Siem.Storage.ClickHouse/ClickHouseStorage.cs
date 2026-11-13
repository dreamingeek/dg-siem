using System.Data.Common;
using ClickHouse.Driver;
using ClickHouse.Driver.ADO.Parameters;
using DreaminGeek.Siem.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

public sealed record StorageDisk(string Name, string Type, string Path, long FreeBytes, long TotalBytes);

/// <summary>Where the events table's data sits: per disk, active parts.</summary>
public sealed record StorageVolume(string Disk, long Rows, long BytesOnDisk, DateTimeOffset? Oldest, DateTimeOffset? Newest);

public sealed record StorageStatus(
    IReadOnlyList<StorageDisk> Disks, IReadOnlyList<StorageVolume> Volumes, string StoragePolicy, string Ttl,
    bool TieredPolicyAvailable, int PendingMutations);

/// <summary>Events and raw bytes per tenant and dataset over a recent window (what each source costs).</summary>
public sealed record StorageUsage(string Tenant, string Dataset, long Events, long RawBytes, int RetentionDays);

/// <summary>An S3-compatible bucket for the cold tier. <paramref name="Endpoint"/> is the bucket URL plus a folder, ending in <c>/</c>.</summary>
public sealed record ColdBucket(string Endpoint, string AccessKeyId, string SecretAccessKey);

/// <summary>
/// Retention and tiering on the events table (Administration &gt; Storage). The cold tier needs a <c>tiered</c>
/// storage policy with a <c>cold</c> volume in ClickHouse's config (deploy/clickhouse/storage-s3.xml); this class
/// switches the table onto it and owns the table's TTL from then on.
/// </summary>
public sealed partial class ClickHouseStorage(ClickHouseClient client, IOptions<ClickHouseOptions> options, ILogger<ClickHouseStorage> logger)
{
    public const string TieredPolicy = "tiered";
    public const string ColdVolume = "cold";
    public const string ColdDisk = "s3_cold";
    public const string ColdCacheDisk = "s3_cold_cache";
    private const string TestObject = "dg-siem-connection-test.csv";
    private string Db => options.Value.Database;
    private string Table => $"{Db}.events";

    public async Task<StorageStatus> GetStatusAsync(CancellationToken ct)
    {
        var disks = new List<StorageDisk>();
        await foreach (var r in Rows("SELECT name, toString(type), path, toInt64(free_space), toInt64(total_space) FROM system.disks ORDER BY name", null, ct))
        {
            disks.Add(new StorageDisk(r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt64(3), r.GetInt64(4)));
        }
        var volumes = new List<StorageVolume>();
        await foreach (var r in Rows(
            "SELECT disk_name, toInt64(sum(rows)), toInt64(sum(bytes_on_disk)), min(min_time), max(max_time) FROM system.parts " +
            "WHERE database = {db:String} AND table = 'events' AND active GROUP BY disk_name ORDER BY disk_name", Db, ct))
        {
            volumes.Add(new StorageVolume(r.GetString(0), r.GetInt64(1), r.GetInt64(2), Time(r, 3), Time(r, 4)));
        }
        string policy = "default", ttl = string.Empty;
        await foreach (var r in Rows("SELECT storage_policy, create_table_query FROM system.tables WHERE database = {db:String} AND name = 'events'", Db, ct))
        {
            policy = r.GetString(0);
            ttl = TtlClause(r.GetString(1));
        }
        var tiered = false;
        await foreach (var _ in Rows($"SELECT 1 FROM system.storage_policies WHERE policy_name = '{TieredPolicy}' AND volume_name = '{ColdVolume}'", null, ct))
        {
            tiered = true;
        }
        var pending = 0;
        await foreach (var r in Rows("SELECT toInt32(count()) FROM system.mutations WHERE database = {db:String} AND table = 'events' AND NOT is_done", Db, ct))
        {
            pending = r.GetInt32(0);
        }
        return new StorageStatus(disks, volumes, policy, ttl, tiered, pending);
    }

    /// <summary>Events and raw size per tenant and dataset over the last <paramref name="days"/> days, largest first.</summary>
    public async Task<IReadOnlyList<StorageUsage>> GetUsageAsync(int days, CancellationToken ct)
    {
        var usage = new List<StorageUsage>();
        var sql = $"SELECT tenant_id, event_dataset, toInt64(count()), toInt64(sum(length(raw) + length(message))), toInt32(max(retention_days)) " +
                  $"FROM {Table} WHERE timestamp >= now64(3) - toIntervalDay({{days:UInt16}}) GROUP BY tenant_id, event_dataset ORDER BY 4 DESC LIMIT 500";
        var parameters = new ClickHouseParameterCollection { new ClickHouseDbParameter { ParameterName = "days", Value = (ushort)days, ClickHouseType = "UInt16" } };
        await using var reader = await client.ExecuteReaderAsync(sql, parameters, ReadOnly(), ct);
        while (await reader.ReadAsync(ct))
        {
            usage.Add(new StorageUsage(reader.GetString(0), reader.GetString(1), reader.GetInt64(2), reader.GetInt64(3), reader.GetInt32(4)));
        }
        return usage;
    }

    /// <summary>
    /// Re-stamps stored events with <paramref name="policy"/>'s retention and recomputes the TTL, so events now past
    /// their retention are deleted at the next merge. Runs as background mutations (see <see cref="StorageStatus.PendingMutations"/>).
    /// </summary>
    public async Task ApplyRetentionToStoredAsync(RetentionPolicy policy, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var values = new Dictionary<string, string>();
        var expression = policy.ToSql(values);
        var parameters = new ClickHouseParameterCollection();
        foreach (var (name, value) in values)
        {
            parameters.Add(new ClickHouseDbParameter { ParameterName = name, Value = value, ClickHouseType = "String" });
        }
        await client.ExecuteNonQueryAsync($"ALTER TABLE {Table} UPDATE retention_days = {expression} WHERE retention_days != {expression}", parameters, cancellationToken: ct);
        await client.ExecuteNonQueryAsync($"ALTER TABLE {Table} MATERIALIZE TTL", cancellationToken: ct);
        LogApplied(logger, values.Count);
    }

    /// <summary>
    /// Sets the table's TTL for the settings: rows deleted at their retention and, with the cold tier on, moved to the
    /// <c>cold</c> volume after <see cref="RetentionSettings.ColdAfterDays"/>. Switches the table to the tiered policy
    /// the first time. Returns a message when the cold tier was asked for but isn't configured in ClickHouse.
    /// </summary>
    public async Task<string?> ApplyTieringAsync(RetentionSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var status = await GetStatusAsync(ct);
        string? problem = null;
        var cold = settings.ColdEnabled;
        if (cold && !status.TieredPolicyAvailable)
        {
            problem = "Cold storage is on, but no bucket is set up yet: add one under Cold storage. Events stay on local disk until then.";
            cold = false;
        }
        if (cold && status.StoragePolicy != TieredPolicy)
        {
            await client.ExecuteNonQueryAsync($"ALTER TABLE {Table} MODIFY SETTING storage_policy = '{TieredPolicy}'", cancellationToken: ct);
            LogTiered(logger);
        }
        var delete = "toDateTime(timestamp) + toIntervalDay(retention_days) DELETE";
        var wanted = cold
            ? $"toDateTime(timestamp) + toIntervalDay({settings.ColdAfterDays}) TO VOLUME '{ColdVolume}', {delete}"
            : delete;
        if (!SameTtl(status.Ttl, wanted))
        {
            // Recompute TTL for existing parts too, so data already older than the threshold moves now.
            await client.ExecuteNonQueryAsync($"ALTER TABLE {Table} MODIFY TTL {wanted}", cancellationToken: ct);
            LogTtl(logger, wanted);
        }
        return problem;
    }

    // ---- Cold-tier bucket ---------------------------------------------------------------------

    /// <summary>
    /// The ClickHouse config for the cold tier: the bucket as disk <c>s3_cold</c> behind a 10 GiB local cache, and the
    /// <c>tiered</c> policy (local <c>default</c> volume, then <c>cold</c>). Same names and paths as the original
    /// deploy/clickhouse/storage-s3.xml, so a cold tier set up that way carries on unchanged.
    /// </summary>
    public static string ColdStorageConfig(ColdBucket bucket, string dataPath)
    {
        ArgumentNullException.ThrowIfNull(bucket);
        var root = dataPath.EndsWith('/') ? dataPath : dataPath + "/";
        var config = new System.Xml.Linq.XElement("clickhouse",
            new System.Xml.Linq.XComment(" Written by DG SIEM (Administration > Storage). Edits here are overwritten. "),
            new System.Xml.Linq.XElement("storage_configuration",
                new System.Xml.Linq.XElement("disks",
                    new System.Xml.Linq.XElement(ColdDisk,
                        new System.Xml.Linq.XElement("type", "s3"),
                        new System.Xml.Linq.XElement("endpoint", bucket.Endpoint),
                        new System.Xml.Linq.XElement("access_key_id", bucket.AccessKeyId),
                        new System.Xml.Linq.XElement("secret_access_key", bucket.SecretAccessKey),
                        new System.Xml.Linq.XElement("metadata_path", $"{root}disks/{ColdDisk}/"),
                        // Some S3-compatible services (B2, GCS) don't do batch deletes; single deletes work everywhere.
                        new System.Xml.Linq.XElement("support_batch_delete", "false"),
                        // The server tests the bucket before saving. Without this, ClickHouse won't start (or reload) while
                        // the bucket is unreachable, taking search and ingest down with it.
                        new System.Xml.Linq.XElement("skip_access_check", "true")),
                    new System.Xml.Linq.XElement(ColdCacheDisk,
                        new System.Xml.Linq.XElement("type", "cache"),
                        new System.Xml.Linq.XElement("disk", ColdDisk),
                        new System.Xml.Linq.XElement("path", $"{root}disks/{ColdCacheDisk}/"),
                        new System.Xml.Linq.XElement("max_size", "10Gi"))),
                new System.Xml.Linq.XElement("policies",
                    new System.Xml.Linq.XElement(TieredPolicy,
                        // Under 10% free locally, ClickHouse moves parts to cold early rather than filling the disk.
                        new System.Xml.Linq.XElement("move_factor", "0.1"),
                        new System.Xml.Linq.XElement("volumes",
                            new System.Xml.Linq.XElement("default", new System.Xml.Linq.XElement("disk", "default")),
                            new System.Xml.Linq.XElement(ColdVolume, new System.Xml.Linq.XElement("disk", ColdCacheDisk)))))));
        return config.ToString() + "\n";
    }

    /// <summary>
    /// Whether ClickHouse can write and read <paramref name="bucket"/>: returns null if so, else ClickHouse's error.
    /// Leaves a one-line <c>dg-siem-connection-test.csv</c> in the folder. The keys go as query parameters, not in the SQL.
    /// </summary>
    public async Task<string?> TestBucketAsync(ColdBucket bucket, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(bucket);
        var parameters = BucketParameters(bucket, bucket.Endpoint + TestObject);
        var options = BucketQuery();
        var marker = Guid.NewGuid().ToString("N");
        parameters.Add(new ClickHouseDbParameter { ParameterName = "marker", Value = marker, ClickHouseType = "String" });
        try
        {
            await client.ExecuteNonQueryAsync(
                "INSERT INTO FUNCTION s3({url:String}, {key:String}, {secret:String}, 'CSV', 'x String') " +
                "SETTINGS s3_truncate_on_insert = 1 SELECT {marker:String}", parameters, options, ct);
            await using var reader = await client.ExecuteReaderAsync(
                "SELECT x FROM s3({url:String}, {key:String}, {secret:String}, 'CSV', 'x String')", BucketParameters(bucket, bucket.Endpoint + TestObject), options, ct);
            return await reader.ReadAsync(ct) && reader.GetString(0) == marker ? null : "The test file read back different from what was written.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return ex.Message;
        }
    }

    /// <summary>Objects ClickHouse has stored under the bucket folder (its keys look like <c>abc/xyz…</c>).</summary>
    public async Task<long> CountBucketObjectsAsync(ColdBucket bucket, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(bucket);
        await using var reader = await client.ExecuteReaderAsync(
            "SELECT count() FROM s3({url:String}, {key:String}, {secret:String}, 'One')", BucketParameters(bucket, bucket.Endpoint + "*/*"), BucketQuery(), ct);
        return await reader.ReadAsync(ct) ? Convert.ToInt64(reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture) : 0;
    }

    /// <summary>Whether ClickHouse has the cold disk loaded, and how many active parts (any table) are on it.</summary>
    public async Task<(bool Loaded, long Parts)> GetColdDiskAsync(CancellationToken ct)
    {
        var loaded = false;
        await foreach (var _ in Rows($"SELECT 1 FROM system.disks WHERE name = '{ColdDisk}'", null, ct))
        {
            loaded = true;
        }
        long parts = 0;
        await foreach (var r in Rows($"SELECT toInt64(count()) FROM system.parts WHERE active AND disk_name IN ('{ColdDisk}', '{ColdCacheDisk}')", null, ct))
        {
            parts = r.GetInt64(0);
        }
        return (loaded, parts);
    }

    /// <summary>Makes ClickHouse re-read its config files (new disks and policies, and changed keys, apply without a restart).</summary>
    public Task ReloadConfigAsync(CancellationToken ct) => client.ExecuteNonQueryAsync("SYSTEM RELOAD CONFIG", cancellationToken: ct);

    private static ClickHouseParameterCollection BucketParameters(ColdBucket bucket, string url) =>
    [
        new ClickHouseDbParameter { ParameterName = "url", Value = url, ClickHouseType = "String" },
        new ClickHouseDbParameter { ParameterName = "key", Value = bucket.AccessKeyId, ClickHouseType = "String" },
        new ClickHouseDbParameter { ParameterName = "secret", Value = bucket.SecretAccessKey, ClickHouseType = "String" },
    ];

    private static QueryOptions BucketQuery() => new()
    {
        MaxExecutionTime = TimeSpan.FromSeconds(30),
        CustomSettings = new Dictionary<string, object>
        {
            ["s3_connect_timeout_ms"] = 5000,
            ["s3_request_timeout_ms"] = 15000,
            ["s3_retry_attempts"] = 1,
        },
    };

    /// <summary>
    /// Whether the table's TTL (as ClickHouse shows it) is already <paramref name="wanted"/>, so a restart doesn't
    /// re-alter the table. ClickHouse leaves out the default <c>DELETE</c> action when it shows a TTL.
    /// </summary>
    public static bool SameTtl(string current, string wanted) =>
        Normalize(current) == Normalize("TTL " + wanted);

    private static string Normalize(string ttl) =>
        string.Concat(ttl.Where(c => !char.IsWhiteSpace(c))).Replace("\"", "'", StringComparison.Ordinal).ToLowerInvariant()
            .Replace("delete", string.Empty, StringComparison.Ordinal);

    /// <summary>The <c>TTL …</c> clause of a CREATE TABLE statement (up to <c>SETTINGS</c>).</summary>
    public static string TtlClause(string createTableQuery)
    {
        var start = createTableQuery.IndexOf(" TTL ", StringComparison.Ordinal);
        if (start < 0)
        {
            return string.Empty;
        }
        var end = createTableQuery.IndexOf(" SETTINGS ", start, StringComparison.Ordinal);
        return (end < 0 ? createTableQuery[(start + 1)..] : createTableQuery[(start + 1)..end]).Trim();
    }

    private static DateTimeOffset? Time(DbDataReader r, int i) =>
        r.IsDBNull(i) ? null : r.GetValue(i) is DateTime d && d.Year > 1971 ? new DateTimeOffset(DateTime.SpecifyKind(d, DateTimeKind.Utc)) : null;

    private static QueryOptions ReadOnly() => new()
    {
        MaxExecutionTime = TimeSpan.FromSeconds(60),
        CustomSettings = new Dictionary<string, object> { ["readonly"] = 2 },
    };

    private async IAsyncEnumerable<DbDataReader> Rows(string sql, string? db, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var parameters = new ClickHouseParameterCollection();
        if (db is not null)
        {
            parameters.Add(new ClickHouseDbParameter { ParameterName = "db", Value = db, ClickHouseType = "String" });
        }
        await using var reader = await client.ExecuteReaderAsync(sql, parameters, ReadOnly(), ct);
        while (await reader.ReadAsync(ct))
        {
            yield return reader;
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Re-stamping stored events with the retention rules ({Parameters} values)")]
    private static partial void LogApplied(ILogger logger, int parameters);

    [LoggerMessage(Level = LogLevel.Information, Message = "Events table switched to the tiered storage policy")]
    private static partial void LogTiered(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Events TTL set to {Ttl}")]
    private static partial void LogTtl(ILogger logger, string ttl);
}
