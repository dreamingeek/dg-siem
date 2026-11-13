using System.Collections.Concurrent;
using System.Net;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Ingest.ThreatIntel;

public interface IThreatIntelEnricher
{
    /// <summary>Marks events whose source or destination address is on an enabled threat feed.</summary>
    void Enrich(LogEvent logEvent);
}

/// <summary>
/// Adds ECS threat fields at ingest when <c>source.ip</c> or <c>destination.ip</c> is on an enabled feed (or your
/// own list). When both are, the destination wins: a machine reaching out to a known-bad server matters most.
/// Does nothing until an index is set (threat intel is off by default).
/// </summary>
public sealed class ThreatIntelEnricher : IThreatIntelEnricher
{
    public const string FeedName = "threat.feed.name";
    public const string MatchedField = "threat.enrichments.matched.field";
    public const string IndicatorIp = "threat.enrichments.indicator.ip";
    public const string IndicatorDescription = "threat.enrichments.indicator.description";
    private const int CacheLimit = 100_000;

    private ThreatIndex? _index;
    private ConcurrentDictionary<string, ThreatMatch?> _cache = new(StringComparer.Ordinal);
    private long _matched;

    public bool IsOn => Volatile.Read(ref _index) is not null;

    /// <summary>Events marked since the server started.</summary>
    public long Matched => Interlocked.Read(ref _matched);

    public int Indicators => Volatile.Read(ref _index)?.Count ?? 0;

    /// <summary>Swaps in a new index; null turns enrichment off.</summary>
    public void Use(ThreatIndex? index)
    {
        Volatile.Write(ref _index, index);
        Interlocked.Exchange(ref _cache, new ConcurrentDictionary<string, ThreatMatch?>(StringComparer.Ordinal));
    }

    /// <summary>What an address matches now, or null (also when threat intel is off).</summary>
    public ThreatMatch? Lookup(string ip)
    {
        var index = Volatile.Read(ref _index);
        if (index is null || ip.Length == 0)
        {
            return null;
        }
        var cache = Volatile.Read(ref _cache);
        if (cache.TryGetValue(ip, out var cached))
        {
            return cached;
        }
        var match = IPAddress.TryParse(ip, out var address) ? index.Find(address) : null;
        if (cache.Count >= CacheLimit)
        {
            cache.Clear();
        }
        cache[ip] = match;
        return match;
    }

    public void Enrich(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (Volatile.Read(ref _index) is null || logEvent.Fields.ContainsKey(FeedName))
        {
            return;
        }
        var (field, ip, match) = Lookup(logEvent.DestinationIp) is { } d ? (EcsField.DestinationIp, logEvent.DestinationIp, d)
            : Lookup(logEvent.SourceIp) is { } s ? (EcsField.SourceIp, logEvent.SourceIp, s)
            : (null, null, null);
        if (match is null)
        {
            return;
        }
        var f = logEvent.Fields;
        f[FeedName] = match.Feed;
        f[MatchedField] = field!;
        f[IndicatorIp] = ip!;
        f[IndicatorDescription] = match.Indicator.Contains('/', StringComparison.Ordinal) ? $"{match.Description}: {match.Indicator}" : match.Description;
        Interlocked.Increment(ref _matched);
    }
}
