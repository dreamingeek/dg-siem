using System.Net;
using DreaminGeek.Siem.Ingest.ThreatIntel;

namespace DreaminGeek.Siem.Tests;

public sealed class ThreatIntelTests
{
    private static ThreatMatch? Find(ThreatIndex index, string ip) => index.Find(IPAddress.Parse(ip));

    [Fact]
    public void Index_matches_addresses_and_ranges_for_both_families()
    {
        var index = ThreatIndex.Build(
        [
            new("203.0.113.7", "own", "seen phishing"),
            new("198.51.100.0/24", "drop", "SBL1"),
            new("2001:db8::/32", "dropv6", "SBL2"),
            new("192.0.2.1", "feodo", "C2"),
            new("not an ip", "junk", "skipped"),
            new("10.0.0.0/33", "junk", "skipped"),
        ]);

        Assert.Equal(4, index.Count);
        Assert.Equal("own", Find(index, "203.0.113.7")!.Feed);
        Assert.Null(Find(index, "203.0.113.8"));
        Assert.Equal("198.51.100.0/24", Find(index, "198.51.100.255")!.Indicator);
        Assert.Null(Find(index, "198.51.101.0"));
        Assert.Equal("dropv6", Find(index, "2001:db8:1234::9")!.Feed);
        Assert.Null(Find(index, "2001:db9::1"));
        Assert.Equal("feodo", Find(index, "::ffff:192.0.2.1")!.Feed); // v4-mapped v6 is the same address
        Assert.Null(Find(index, "8.8.8.8"));
    }

    [Fact]
    public void Overlapping_ranges_find_the_narrowest_and_earlier_wide_ranges_still_match()
    {
        var index = ThreatIndex.Build(
        [
            new("10.0.0.0/8", "wide", "a"),
            new("10.1.0.0/16", "middle", "b"),
            new("10.1.2.0/24", "narrow", "c"),
            new("10.200.0.0/16", "later", "d"),
        ]);

        Assert.Equal("narrow", Find(index, "10.1.2.3")!.Feed);
        Assert.Equal("middle", Find(index, "10.1.3.3")!.Feed);
        // After 10.200.0.0/16 in sort order, but only the /8 that started earlier covers it.
        Assert.Equal("wide", Find(index, "10.255.0.1")!.Feed);
        Assert.Equal("later", Find(index, "10.200.9.9")!.Feed);
    }

    [Fact]
    public void First_listing_wins_for_the_same_address()
    {
        var index = ThreatIndex.Build([new("192.0.2.1", "own", "mine"), new("192.0.2.1", "feodo", "theirs")]);
        Assert.Equal("own", Find(index, "192.0.2.1")!.Feed);
    }

    [Fact]
    public void Spamhaus_drop_skips_the_metadata_line()
    {
        const string drop = """
            {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
            {"cidr":"2.56.192.0/22","sblid":"SBL459831","rir":"ripencc"}
            {"type":"metadata","timestamp":1762905600,"size":2,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU"}
            """;
        var list = ThreatFeeds.Parse(ThreatFeedFormat.SpamhausDrop, drop, "Spamhaus DROP");
        Assert.Equal(["1.10.16.0/20", "2.56.192.0/22"], list.Select(i => i.Value));
        Assert.Equal("Listed on DROP (SBL256894)", list[0].Description);
    }

    [Fact]
    public void Feodo_and_threatfox_read_their_json()
    {
        const string feodo = """
            [{"ip_address":"162.243.103.246","port":8080,"status":"offline","hostname":null,"as_number":14061,"as_name":"DIGITALOCEAN-ASN","country":"US","first_seen":"2021-01-17 07:44:46","last_online":"2026-03-04","malware":"Emotet"}]
            """;
        var f = ThreatFeeds.Parse(ThreatFeedFormat.FeodoJson, feodo, "Feodo Tracker");
        Assert.Equal("162.243.103.246", Assert.Single(f).Value);
        Assert.Equal("Botnet C2: Emotet (offline)", f[0].Description);

        const string threatfox = """
            {"1802589":[{"ioc_value":"158.94.211.33:7017","ioc_type":"ip:port","threat_type":"botnet_cc","malware":"win.xworm","malware_alias":null,"malware_printable":"XWorm","first_seen_utc":"2026-11-12 18:01:12","last_seen_utc":null,"confidence_level":75,"is_compromised":false,"reference":null,"tags":"XWorm","anonymous":"0","reporter":"abuse_ch"}],
             "1802590":[{"ioc_value":"[2001:db8::5]:443","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"Unknown Stealer","first_seen_utc":"2026-11-12 19:00:00","last_seen_utc":"2026-11-13 01:00:00"}],
             "1802591":[{"ioc_value":"evil.example.com","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"X"}]}
            """;
        var t = ThreatFeeds.Parse(ThreatFeedFormat.ThreatFoxJson, threatfox, "ThreatFox");
        Assert.Equal(["158.94.211.33", "2001:db8::5"], t.Select(i => i.Value));
        Assert.Equal("C2: XWorm", t[0].Description);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 18, 1, 12, TimeSpan.Zero), t[0].LastSeen);
        Assert.Equal(new DateTimeOffset(2026, 11, 13, 1, 0, 0, TimeSpan.Zero), t[1].LastSeen);
    }

    [Fact]
    public void Plain_lists_take_the_first_word_of_each_line()
    {
        const string text = """
            # Tor exit list
            185.220.101.1
            203.0.113.0/24  scanner range ; note
            203.0.113.9,with,csv
            ; comment
            not-an-address
            """;
        var list = ThreatFeeds.Parse(ThreatFeedFormat.PlainText, text, "Custom");
        Assert.Equal(["185.220.101.1", "203.0.113.0/24", "203.0.113.9"], list.Select(i => i.Value));
    }

    [Fact]
    public void Wrong_format_is_an_error_not_an_empty_list()
    {
        Assert.Throws<FormatException>(() => ThreatFeeds.Parse(ThreatFeedFormat.FeodoJson, "<html>blocked</html>", "Feodo"));
        Assert.Throws<FormatException>(() => ThreatFeeds.Parse(ThreatFeedFormat.SpamhausDrop, "<html>rate limited</html>", "DROP"));
    }

    private static DreaminGeek.Siem.Core.LogEvent Event(string src, string dst) =>
        new() { Timestamp = DateTimeOffset.UtcNow, TenantId = "dg", Raw = "x", SourceIp = src, DestinationIp = dst };

    [Fact]
    public void Enricher_marks_events_and_prefers_the_destination()
    {
        var enricher = new ThreatIntelEnricher();
        var e = Event("192.168.1.10", "198.51.100.20");
        enricher.Enrich(e);
        Assert.Empty(e.Fields); // off until an index is set

        enricher.Use(ThreatIndex.Build([new("198.51.100.0/24", "Spamhaus DROP", "Listed on DROP (SBL1)"), new("203.0.113.5", "Feodo Tracker", "Botnet C2: QakBot")]));
        enricher.Enrich(e);
        Assert.Equal("Spamhaus DROP", e.Fields[ThreatIntelEnricher.FeedName]);
        Assert.Equal("destination.ip", e.Fields[ThreatIntelEnricher.MatchedField]);
        Assert.Equal("198.51.100.20", e.Fields[ThreatIntelEnricher.IndicatorIp]);
        Assert.Equal("Listed on DROP (SBL1): 198.51.100.0/24", e.Fields[ThreatIntelEnricher.IndicatorDescription]);

        var inbound = Event("203.0.113.5", "192.168.1.10");
        enricher.Enrich(inbound);
        Assert.Equal("source.ip", inbound.Fields[ThreatIntelEnricher.MatchedField]);
        Assert.Equal("Botnet C2: QakBot", inbound.Fields[ThreatIntelEnricher.IndicatorDescription]);

        var both = Event("203.0.113.5", "198.51.100.1");
        enricher.Enrich(both);
        Assert.Equal("destination.ip", both.Fields[ThreatIntelEnricher.MatchedField]);

        var clean = Event("8.8.8.8", "");
        enricher.Enrich(clean);
        Assert.False(clean.Fields.ContainsKey(ThreatIntelEnricher.FeedName));
        Assert.Equal(3, enricher.Matched);

        enricher.Use(null);
        var after = Event("203.0.113.5", "");
        enricher.Enrich(after);
        Assert.Empty(after.Fields);
    }

    [Fact]
    public void Recent_sighting_feeds_keep_addresses_for_their_window()
    {
        var threatfox = ThreatFeeds.BuiltIn.Single(f => f.Id == "threatfox");
        var drop = ThreatFeeds.BuiltIn.Single(f => f.Id == "spamhaus-drop-v4");
        var now = new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
        List<ThreatIndicator> kept =
        [
            new("192.0.2.1", "ThreatFox", "C2: Old", now.AddDays(-31)),   // past 30 days: dropped
            new("192.0.2.2", "ThreatFox", "C2: Recent", now.AddDays(-3)), // kept though not in this download
            new("192.0.2.3", "ThreatFox", "C2: Again", now.AddDays(-10)),
        ];
        List<ThreatIndicator> downloaded = [new("192.0.2.3", "ThreatFox", "C2: Again", null), new("192.0.2.4", "ThreatFox", "C2: New", now.AddHours(-2))];

        var merged = DreaminGeek.Siem.Web.ThreatIntel.ThreatIntelService.Merge(threatfox, kept, downloaded, now).OrderBy(i => i.Value, StringComparer.Ordinal).ToList();
        Assert.Equal(["192.0.2.2", "192.0.2.3", "192.0.2.4"], merged.Select(i => i.Value));
        Assert.Equal(now, merged[1].LastSeen); // seen again now

        // A whole-list feed simply replaces what it had.
        Assert.Equal(downloaded, DreaminGeek.Siem.Web.ThreatIntel.ThreatIntelService.Merge(drop, kept, downloaded, now));
    }

    [Fact]
    public void Built_in_feeds_respect_publisher_limits()
    {
        Assert.All(ThreatFeeds.BuiltIn.Where(f => f.Url.Contains("spamhaus", StringComparison.Ordinal)), f => Assert.True(f.Interval >= TimeSpan.FromDays(1)));
        Assert.All(ThreatFeeds.BuiltIn, f => Assert.StartsWith("https://", f.Url, StringComparison.Ordinal));
        // Feeds whose terms restrict commercial use stay off unless switched on, and say why.
        Assert.False(ThreatFeeds.BuiltIn.Single(f => f.Id == "threatfox").OnByDefault);
        Assert.NotNull(ThreatFeeds.BuiltIn.Single(f => f.Id == "threatfox").Caution);
    }
}
