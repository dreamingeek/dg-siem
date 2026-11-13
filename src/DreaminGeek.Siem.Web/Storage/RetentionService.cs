using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web.Admin;

namespace DreaminGeek.Siem.Web.Storage;

/// <summary>
/// Retention rules and the cold tier (Administration &gt; Storage): saved in PostgreSQL, applied to ingest (each
/// event's retention_days) and to the ClickHouse table's TTL. Loaded at startup.
/// </summary>
public sealed partial class RetentionService(SettingsStore settings, RetentionPolicy policy, ClickHouseStorage storage, ColdStorageService coldStorage, ILogger<RetentionService> logger) : IHostedService
{
    /// <summary>Why the last attempt to apply tiering didn't fully work, or null.</summary>
    public string? Problem { get; private set; }

    public RetentionSettings Current => policy.Settings;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            var saved = await settings.GetRetentionAsync(cancellationToken);
            policy.Update(saved);
            // The bucket's config first (it may need rewriting after a recreated volume or a restore), then the TTL.
            var bucketProblem = await coldStorage.EnsureAsync(cancellationToken);
            Problem = bucketProblem ?? await storage.ApplyTieringAsync(saved, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Ingest still uses the rules it loaded (or the defaults); the Storage page shows the problem.
            Problem = $"Couldn't apply the storage settings to ClickHouse: {ex.Message}";
            LogStartFailed(logger, ex.Message);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Validates, saves, and applies to new events and the table's TTL. Returns a warning, if any.</summary>
    public async Task<string?> SaveAsync(RetentionSettings value, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(value);
        var normalized = value with
        {
            Rules = value.Rules
                .Select(r => r with { Tenant = string.IsNullOrWhiteSpace(r.Tenant) ? null : r.Tenant.Trim().ToLowerInvariant(), Dataset = r.Dataset.Trim().ToLowerInvariant() })
                .ToList(),
        };
        if (normalized.Validate().FirstOrDefault() is { } error)
        {
            throw new AdminException(error);
        }
        await settings.SaveRetentionAsync(normalized, ct);
        policy.Update(normalized);
        Problem = await storage.ApplyTieringAsync(normalized, ct);
        return Problem;
    }

    /// <summary>After the bucket is set up: applies the saved cold-tier settings now that the policy exists.</summary>
    public async Task<string?> ReapplyTieringAsync(CancellationToken ct)
    {
        Problem = await storage.ApplyTieringAsync(policy.Settings, ct);
        return Problem;
    }

    /// <summary>Re-stamps events already stored with the current rules (shortening a rule deletes data).</summary>
    public Task ApplyToStoredAsync(CancellationToken ct) => storage.ApplyRetentionToStoredAsync(policy, ct);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Couldn't apply storage settings at startup: {Reason}")]
    private static partial void LogStartFailed(ILogger logger, string reason);
}
