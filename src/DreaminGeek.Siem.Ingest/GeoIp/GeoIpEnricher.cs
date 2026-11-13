using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DreaminGeek.Siem.Core;
using MaxMind.Db;

namespace DreaminGeek.Siem.Ingest.GeoIp;

/// <summary>What one address resolves to. Any part may be missing.</summary>
public sealed record GeoIpResult(
    string? CountryCode, string? CountryName, string? Region, string? City, string? ContinentCode,
    double? Latitude, double? Longitude, long? AsNumber, string? AsOrganization)
{
    public bool IsEmpty => CountryCode is null && AsNumber is null;
}

/// <summary>The loaded databases, for the status page.</summary>
public sealed record GeoIpDatabaseInfo(string Kind, string DatabaseType, DateTime BuildDate, string Path);

public interface IGeoIpEnricher
{
    /// <summary>Adds <c>source.geo.*</c> / <c>source.as.*</c> (and destination) for public addresses.</summary>
    void Enrich(LogEvent logEvent);
}

/// <summary>
/// Looks addresses up in MMDB files (DB-IP Lite, MaxMind GeoLite2/GeoIP2, or compatible) and adds ECS geo and
/// AS fields at ingest. Private and reserved addresses are skipped, and fields a parser already set (e.g.
/// CrowdSec's country) are kept. Databases can be swapped while running; lookups are cached per address.
/// </summary>
public sealed class GeoIpEnricher : IGeoIpEnricher, IDisposable
{
    private const int CacheLimit = 100_000;

    private Databases? _databases;
    private ConcurrentDictionary<IPAddress, GeoIpResult?> _cache = new();
    private long _lookups;
    private long _enriched;

    public bool EnrichDestination { get; set; } = true;

    public bool IsLoaded => Volatile.Read(ref _databases) is { } d && (d.City is not null || d.Asn is not null);
    public long Lookups => Interlocked.Read(ref _lookups);
    public long Enriched => Interlocked.Read(ref _enriched);

    public IReadOnlyList<GeoIpDatabaseInfo> Loaded
    {
        get
        {
            var d = Volatile.Read(ref _databases);
            var list = new List<GeoIpDatabaseInfo>();
            if (d?.City is { } c)
            {
                list.Add(new GeoIpDatabaseInfo("city", c.Reader.Metadata.DatabaseType, c.Reader.Metadata.BuildDate, c.Path));
            }
            if (d?.Asn is { } a)
            {
                list.Add(new GeoIpDatabaseInfo("asn", a.Reader.Metadata.DatabaseType, a.Reader.Metadata.BuildDate, a.Path));
            }
            return list;
        }
    }

    /// <summary>Opens the files (either may be null) and swaps them in. Throws if a file isn't a valid MMDB.</summary>
    public void Load(string? cityPath, string? asnPath)
    {
        var city = cityPath is not null && File.Exists(cityPath) ? new Opened(new Reader(cityPath, FileAccessMode.MemoryMapped), cityPath) : null;
        Opened? asn;
        try
        {
            asn = asnPath is not null && File.Exists(asnPath) ? new Opened(new Reader(asnPath, FileAccessMode.MemoryMapped), asnPath) : null;
        }
        catch
        {
            city?.Reader.Dispose();
            throw;
        }
        var old = Interlocked.Exchange(ref _databases, new Databases(city, asn));
        Interlocked.Exchange(ref _cache, new ConcurrentDictionary<IPAddress, GeoIpResult?>());
        Retire(old);
    }

    public void Unload()
    {
        Retire(Interlocked.Exchange(ref _databases, null));
        Interlocked.Exchange(ref _cache, new ConcurrentDictionary<IPAddress, GeoIpResult?>());
    }

    /// <summary>Opens a file just to check it's a usable MMDB of the expected kind (for downloads).</summary>
    public static GeoIpDatabaseInfo Inspect(string path, string kind)
    {
        // Memory-mapped: only the metadata pages are actually read, not the whole (100+ MB) file.
        using var reader = new Reader(path, FileAccessMode.MemoryMapped);
        return new GeoIpDatabaseInfo(kind, reader.Metadata.DatabaseType, reader.Metadata.BuildDate, path);
    }

    public void Enrich(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (Volatile.Read(ref _databases) is null)
        {
            return;
        }
        var added = Apply(logEvent, "source", logEvent.SourceIp);
        if (EnrichDestination)
        {
            added |= Apply(logEvent, "destination", logEvent.DestinationIp);
        }
        if (added)
        {
            Interlocked.Increment(ref _enriched);
        }
    }

    private bool Apply(LogEvent e, string prefix, string ip)
    {
        if (ip.Length == 0 || !IPAddress.TryParse(ip, out var address) || !IpRanges.IsPublic(address))
        {
            return false;
        }
        if (Lookup(address) is not { IsEmpty: false } r)
        {
            return false;
        }
        var f = e.Fields;
        var countryKey = $"{prefix}.geo.country_iso_code";
        // A parser that knows better (CrowdSec, authentik) already set the location; keep it.
        if (!f.ContainsKey(countryKey) && r.CountryCode is not null)
        {
            f[countryKey] = r.CountryCode;
            Set(f, $"{prefix}.geo.country_name", r.CountryName);
            Set(f, $"{prefix}.geo.region_name", r.Region);
            Set(f, $"{prefix}.geo.city_name", r.City);
            Set(f, $"{prefix}.geo.continent_code", r.ContinentCode);
            if (r.Latitude is { } lat && r.Longitude is { } lon)
            {
                f[$"{prefix}.geo.location.lat"] = lat.ToString("0.####", CultureInfo.InvariantCulture);
                f[$"{prefix}.geo.location.lon"] = lon.ToString("0.####", CultureInfo.InvariantCulture);
            }
        }
        if (!f.ContainsKey($"{prefix}.as.number") && r.AsNumber is { } asn)
        {
            f[$"{prefix}.as.number"] = asn.ToString(CultureInfo.InvariantCulture);
            Set(f, $"{prefix}.as.organization.name", r.AsOrganization);
        }
        return true;
    }

    /// <summary>Looks one address up (cached). Null when nothing is loaded or the address isn't in the databases.</summary>
    public GeoIpResult? Lookup(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var databases = Volatile.Read(ref _databases);
        if (databases is null)
        {
            return null;
        }
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        var cache = Volatile.Read(ref _cache);
        if (cache.TryGetValue(address, out var cached))
        {
            return cached;
        }
        Interlocked.Increment(ref _lookups);
        var result = Find(databases, address);
        if (cache.Count >= CacheLimit)
        {
            cache.Clear();
        }
        cache[address] = result;
        return result;
    }

    private static GeoIpResult? Find(Databases d, IPAddress address)
    {
        Dictionary<string, object>? city = null, asn = null;
        try
        {
            city = d.City?.Reader.Find<Dictionary<string, object>>(address);
            asn = d.Asn?.Reader.Find<Dictionary<string, object>>(address);
        }
        catch (InvalidDatabaseException)
        {
            return null;
        }
        catch (ObjectDisposedException)
        {
            // Swapped out mid-lookup; the next event uses the new files.
            return null;
        }
        if (city is null && asn is null)
        {
            return null;
        }
        var result = new GeoIpResult(
            Text(city, "country", "iso_code") ?? Text(city, "registered_country", "iso_code"),
            Name(city, "country") ?? Name(city, "registered_country"),
            city?.GetValueOrDefault("subdivisions") is System.Collections.IList { Count: > 0 } subs && subs[0] is Dictionary<string, object> sub ? Name(sub) : null,
            Name(city, "city"),
            Text(city, "continent", "code"),
            Number(city, "location", "latitude"),
            Number(city, "location", "longitude"),
            asn?.GetValueOrDefault("autonomous_system_number") is { } n ? Convert.ToInt64(n, CultureInfo.InvariantCulture) : null,
            asn?.GetValueOrDefault("autonomous_system_organization") as string);
        return result.IsEmpty ? null : result;
    }

    private static string? Text(Dictionary<string, object>? data, string outer, string inner) =>
        data?.GetValueOrDefault(outer) is Dictionary<string, object> o && o.GetValueOrDefault(inner) is string { Length: > 0 } s ? s : null;

    private static string? Name(Dictionary<string, object>? data, string outer) =>
        data?.GetValueOrDefault(outer) is Dictionary<string, object> o ? Name(o) : null;

    private static string? Name(Dictionary<string, object> o) =>
        o.GetValueOrDefault("names") is Dictionary<string, object> names && names.GetValueOrDefault("en") is string { Length: > 0 } s ? s : null;

    private static double? Number(Dictionary<string, object>? data, string outer, string inner) =>
        data?.GetValueOrDefault(outer) is Dictionary<string, object> o && o.GetValueOrDefault(inner) is IConvertible c
            ? c.ToDouble(CultureInfo.InvariantCulture) : null;

    private static void Set(Dictionary<string, string> fields, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            fields[key] = value;
        }
    }

    /// <summary>Old readers are disposed after a grace period, so lookups in flight finish.</summary>
    private static void Retire(Databases? old)
    {
        if (old is null)
        {
            return;
        }
        _ = Task.Delay(TimeSpan.FromSeconds(30)).ContinueWith(_ =>
        {
            old.City?.Reader.Dispose();
            old.Asn?.Reader.Dispose();
        }, TaskScheduler.Default);
    }

    public void Dispose()
    {
        var d = Interlocked.Exchange(ref _databases, null);
        d?.City?.Reader.Dispose();
        d?.Asn?.Reader.Dispose();
    }

    private sealed record Opened(Reader Reader, string Path);

    private sealed record Databases(Opened? City, Opened? Asn);
}

/// <summary>Enrichment disabled (no databases configured).</summary>
public sealed class NoGeoIp : IGeoIpEnricher
{
    public void Enrich(LogEvent logEvent)
    {
    }
}

/// <summary>Which addresses are worth looking up: not private, loopback, link-local, CGNAT, documentation, etc.</summary>
public static class IpRanges
{
    private static readonly (IPAddress Network, int Prefix)[] NonPublic =
    [
        (IPAddress.Parse("0.0.0.0"), 8),
        (IPAddress.Parse("10.0.0.0"), 8),
        (IPAddress.Parse("100.64.0.0"), 10),   // CGNAT (also Pangolin/newt and Tailscale tunnels)
        (IPAddress.Parse("127.0.0.0"), 8),
        (IPAddress.Parse("169.254.0.0"), 16),
        (IPAddress.Parse("172.16.0.0"), 12),
        (IPAddress.Parse("192.0.0.0"), 24),
        (IPAddress.Parse("192.0.2.0"), 24),    // documentation
        (IPAddress.Parse("192.168.0.0"), 16),
        (IPAddress.Parse("198.18.0.0"), 15),
        (IPAddress.Parse("198.51.100.0"), 24), // documentation
        (IPAddress.Parse("203.0.113.0"), 24),  // documentation
        (IPAddress.Parse("224.0.0.0"), 4),     // multicast
        (IPAddress.Parse("240.0.0.0"), 4),     // reserved + broadcast
        (IPAddress.Parse("::"), 128),
        (IPAddress.Parse("::1"), 128),
        (IPAddress.Parse("fc00::"), 7),        // unique local
        (IPAddress.Parse("fe80::"), 10),       // link-local
        (IPAddress.Parse("ff00::"), 8),        // multicast
        (IPAddress.Parse("2001:db8::"), 32),   // documentation
    ];

    public static bool IsPublic(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        foreach (var (network, prefix) in NonPublic)
        {
            if (network.AddressFamily == address.AddressFamily && new IPNetwork(network, prefix).Contains(address))
            {
                return false;
            }
        }
        return address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
    }
}
