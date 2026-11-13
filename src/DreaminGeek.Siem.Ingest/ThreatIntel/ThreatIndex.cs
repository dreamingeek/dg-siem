using System.Net;
using System.Net.Sockets;

namespace DreaminGeek.Siem.Ingest.ThreatIntel;

/// <summary>One bad address or range from a feed: <c>203.0.113.7</c>, <c>198.51.100.0/24</c>, <c>2001:db8::/32</c>.</summary>
/// <param name="LastSeen">When the feed last saw it, for feeds that are merged over time (null: as long as it's listed).</param>
public sealed record ThreatIndicator(string Value, string Feed, string Description, DateTimeOffset? LastSeen = null);

/// <summary>What an address matched: the feed, why it's listed, and the listed address or range.</summary>
public sealed record ThreatMatch(string Feed, string Description, string Indicator);

/// <summary>
/// Every enabled feed's indicators in one immutable lookup: single addresses in a hash set, ranges sorted by start
/// with the furthest end seen so far, so a lookup is a binary search plus a short walk back even when ranges
/// overlap. IPv4 is stored as IPv4-mapped IPv6, so one index covers both.
/// </summary>
public sealed class ThreatIndex
{
    public static ThreatIndex Empty { get; } = Build([]);

    private readonly Dictionary<UInt128, ThreatIndicator> _addresses;
    private readonly UInt128[] _starts;
    private readonly UInt128[] _ends;
    private readonly UInt128[] _maxEnd;
    private readonly ThreatIndicator[] _ranges;

    private ThreatIndex(Dictionary<UInt128, ThreatIndicator> addresses, List<(UInt128 Start, UInt128 End, ThreatIndicator Indicator)> ranges)
    {
        _addresses = addresses;
        ranges.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : b.End.CompareTo(a.End));
        _starts = ranges.Select(r => r.Start).ToArray();
        _ends = ranges.Select(r => r.End).ToArray();
        _ranges = ranges.Select(r => r.Indicator).ToArray();
        _maxEnd = new UInt128[ranges.Count];
        for (var i = 0; i < ranges.Count; i++)
        {
            _maxEnd[i] = i == 0 || _ends[i] > _maxEnd[i - 1] ? _ends[i] : _maxEnd[i - 1];
        }
    }

    /// <summary>Addresses plus ranges.</summary>
    public int Count => _addresses.Count + _ranges.Length;

    /// <summary>
    /// Builds the index. When the same address or range is listed twice, the first indicator wins, so pass the
    /// most trusted feeds (your own list) first. Values that aren't an address or range are skipped.
    /// </summary>
    public static ThreatIndex Build(IEnumerable<ThreatIndicator> indicators)
    {
        ArgumentNullException.ThrowIfNull(indicators);
        var addresses = new Dictionary<UInt128, ThreatIndicator>();
        var ranges = new List<(UInt128, UInt128, ThreatIndicator)>();
        var seenRanges = new HashSet<(UInt128, UInt128)>();
        foreach (var indicator in indicators)
        {
            if (!TryParse(indicator.Value, out var start, out var end))
            {
                continue;
            }
            if (start == end)
            {
                addresses.TryAdd(start, indicator);
            }
            else if (seenRanges.Add((start, end)))
            {
                ranges.Add((start, end, indicator));
            }
        }
        return new ThreatIndex(addresses, ranges);
    }

    /// <summary>The indicator <paramref name="address"/> falls under: an exact address first, else the narrowest range.</summary>
    public ThreatMatch? Find(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var key = ToKey(address);
        if (_addresses.TryGetValue(key, out var exact))
        {
            return new ThreatMatch(exact.Feed, exact.Description, exact.Value);
        }
        // Last range starting at or before the address, then back while an earlier range could still reach it.
        var i = Array.BinarySearch(_starts, key);
        if (i < 0)
        {
            i = ~i - 1;
        }
        ThreatIndicator? best = null;
        var bestSize = UInt128.MaxValue;
        for (; i >= 0 && _maxEnd[i] >= key; i--)
        {
            if (_ends[i] >= key && _ends[i] - _starts[i] < bestSize)
            {
                best = _ranges[i];
                bestSize = _ends[i] - _starts[i];
            }
        }
        return best is null ? null : new ThreatMatch(best.Feed, best.Description, best.Value);
    }

    /// <summary>
    /// Parses an address or CIDR range into its first and last address (IPv4 as IPv4-mapped IPv6). A range's host
    /// bits are ignored (<c>10.1.2.3/8</c> is <c>10.0.0.0/8</c>).
    /// </summary>
    public static bool TryParse(string value, out UInt128 start, out UInt128 end)
    {
        start = end = UInt128.Zero;
        var text = value.AsSpan().Trim();
        var slash = text.IndexOf('/');
        var addressText = slash < 0 ? text : text[..slash];
        if (!IPAddress.TryParse(addressText, out var address))
        {
            return false;
        }
        var v4 = address.AddressFamily == AddressFamily.InterNetwork || address.IsIPv4MappedToIPv6;
        var bits = v4 ? 32 : 128;
        var prefix = bits;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > bits))
        {
            return false;
        }
        var key = ToKey(address);
        var hostBits = bits - prefix;
        var mask = hostBits == 0 ? UInt128.Zero : hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
        start = key & ~mask;
        end = start | mask;
        return true;
    }

    private static UInt128 ToKey(IPAddress address)
    {
        var bytes = (address.AddressFamily == AddressFamily.InterNetwork ? address.MapToIPv6() : address).GetAddressBytes();
        return new UInt128(
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0, 8)),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(8, 8)));
    }
}
