using System.Collections.Concurrent;

namespace DreaminGeek.Siem.Ingest.Metrics;

/// <summary>
/// Why each failing scrape target failed, as its agent reported it, for the Health page and alerts. Kept in memory
/// only: after a restart it fills in again with the next scrape.
/// </summary>
public sealed class ScrapeErrors
{
    private readonly ConcurrentDictionary<(string Tenant, string Job, string Instance), (DateTimeOffset At, string Error)> _errors = new();

    public void Record(string tenant, string job, string instance, DateTimeOffset at, string? error)
    {
        var key = (tenant, job, instance);
        if (error is null)
        {
            _errors.TryRemove(key, out _);
        }
        else
        {
            _errors[key] = (at, error);
        }
    }

    /// <summary>The last error for a target, or null if its last scrape worked (or none has been seen since start).</summary>
    public string? Get(string tenant, string job, string instance) =>
        _errors.TryGetValue((tenant, job, instance), out var e) ? e.Error : null;
}
