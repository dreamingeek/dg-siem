using System.Net;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Ingest.GeoIp;

namespace DreaminGeek.Siem.Tests;

public sealed class GeoIpTests : IDisposable
{
    private static readonly string Data = Path.Combine(AppContext.BaseDirectory, "TestData");
    private readonly GeoIpEnricher _geo = new();

    public GeoIpTests() => _geo.Load(Path.Combine(Data, "geo-city-test.mmdb"), Path.Combine(Data, "geo-asn-test.mmdb"));

    public void Dispose() => _geo.Dispose();

    private static LogEvent Event(string src, string dst = "") => new()
    {
        TenantId = "dg", Timestamp = DateTimeOffset.UtcNow, SourceIp = src, DestinationIp = dst, EventDataset = "traefik.access", Raw = "x",
    };

    [Fact]
    public void PublicSourceGetsLocationAndNetwork()
    {
        var e = Event("81.2.69.142");
        _geo.Enrich(e);

        Assert.Equal("GB", e.Fields["source.geo.country_iso_code"]);
        Assert.Equal("United Kingdom", e.Fields["source.geo.country_name"]);
        Assert.Equal("London", e.Fields["source.geo.city_name"]);
        Assert.Equal("England", e.Fields["source.geo.region_name"]);
        Assert.Equal("EU", e.Fields["source.geo.continent_code"]);
        Assert.Equal("51.5142", e.Fields["source.geo.location.lat"]);
        Assert.Equal("-0.0931", e.Fields["source.geo.location.lon"]);
        Assert.Equal("20712", e.Fields["source.as.number"]);
        Assert.Equal("Andrews & Arnold Ltd", e.Fields["source.as.organization.name"]);
        Assert.Equal(1, _geo.Enriched);
    }

    [Fact]
    public void DestinationIsEnrichedUnlessTurnedOff()
    {
        var e = Event("192.168.1.20", "45.148.10.12");
        _geo.Enrich(e);
        Assert.Equal("NL", e.Fields["destination.geo.country_iso_code"]);
        Assert.Equal("48090", e.Fields["destination.as.number"]);
        Assert.False(e.Fields.ContainsKey("source.geo.country_iso_code"));

        _geo.EnrichDestination = false;
        var off = Event("192.168.1.20", "45.148.10.12");
        _geo.Enrich(off);
        Assert.Empty(off.Fields);
    }

    [Fact]
    public void ParserSuppliedLocationIsKept()
    {
        // CrowdSec reports its own country; GeoIP still fills the network if it's missing.
        var e = Event("45.148.10.12");
        e.Fields["source.geo.country_iso_code"] = "DE";
        _geo.Enrich(e);
        Assert.Equal("DE", e.Fields["source.geo.country_iso_code"]);
        Assert.False(e.Fields.ContainsKey("source.geo.city_name"));
        Assert.Equal("Techoff SRV Limited", e.Fields["source.as.organization.name"]);
    }

    [Fact]
    public void CountryOnlyNetworksAndIpv6()
    {
        var cn = Event("1.12.34.56");
        _geo.Enrich(cn);
        Assert.Equal("CN", cn.Fields["source.geo.country_iso_code"]);
        Assert.False(cn.Fields.ContainsKey("source.geo.city_name"));
        Assert.False(cn.Fields.ContainsKey("source.as.number"));

        var v6 = Event("2001:4860:4860::8888");
        _geo.Enrich(v6);
        Assert.Equal("Mountain View", v6.Fields["source.geo.city_name"]);

        var mapped = Event("::ffff:81.2.69.142");
        _geo.Enrich(mapped);
        Assert.Equal("GB", mapped.Fields["source.geo.country_iso_code"]);
    }

    [Theory]
    [InlineData("192.168.1.20")]
    [InlineData("100.64.0.4")]      // Pangolin/newt tunnel (CGNAT)
    [InlineData("172.18.0.4")]        // Docker
    [InlineData("192.168.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.10.1")]
    [InlineData("203.0.113.5")]       // documentation
    [InlineData("fe80::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("::1")]
    [InlineData("not an ip")]
    [InlineData("")]
    public void PrivateAndReservedAddressesAreSkipped(string ip)
    {
        var e = Event(ip);
        _geo.Enrich(e);
        Assert.Empty(e.Fields);
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("216.160.83.56", true)]
    [InlineData("2606:4700::1111", true)]
    [InlineData("100.63.255.255", true)]
    [InlineData("100.64.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("172.31.255.255", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    public void PublicAddressCheck(string ip, bool expected) =>
        Assert.Equal(expected, IpRanges.IsPublic(IPAddress.Parse(ip)));

    [Fact]
    public void UnknownAddressesAddNothingAndAreCached()
    {
        var e = Event("8.8.8.8");
        _geo.Enrich(e);
        _geo.Enrich(Event("8.8.8.8"));
        Assert.Empty(e.Fields);
        Assert.Equal(1, _geo.Lookups);
    }

    [Fact]
    public void ReportsLoadedDatabases()
    {
        Assert.Equal(["DG-Test-City", "DG-Test-ASN"], _geo.Loaded.Select(d => d.DatabaseType));
        Assert.Equal("DG-Test-City", GeoIpEnricher.Inspect(Path.Combine(Data, "geo-city-test.mmdb"), "city").DatabaseType);
    }

    [Fact]
    public void NothingLoadedMeansNoChanges()
    {
        using var empty = new GeoIpEnricher();
        var e = Event("81.2.69.142");
        empty.Enrich(e);
        Assert.Empty(e.Fields);
        Assert.False(empty.IsLoaded);
    }
}

public class GeoIpPipelineTests
{
    private sealed class CapturingSink : DreaminGeek.Siem.Core.IEventSink
    {
        public System.Collections.Concurrent.ConcurrentQueue<LogEvent> Events { get; } = new();

        public Task WriteAsync(IReadOnlyList<LogEvent> batch, CancellationToken cancellationToken)
        {
            foreach (var e in batch)
            {
                Events.Enqueue(e);
            }
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task IngestedEventsAreEnrichedAfterParsing()
    {
        var data = Path.Combine(AppContext.BaseDirectory, "TestData");
        using var geo = new GeoIpEnricher();
        geo.Load(Path.Combine(data, "geo-city-test.mmdb"), Path.Combine(data, "geo-asn-test.mmdb"));
        var sink = new CapturingSink();
        var parsers = new DreaminGeek.Siem.Parsers.ParserRegistry([new DreaminGeek.Siem.Parsers.Vendors.TraefikParser(), new DreaminGeek.Siem.Parsers.SyslogParser()]);
        var pipeline = new DreaminGeek.Siem.Ingest.IngestPipeline(parsers, sink,
            new DreaminGeek.Siem.Ingest.DropFilter(new DreaminGeek.Siem.Ingest.NoDropRules()),
            geo, Microsoft.Extensions.Options.Options.Create(new DreaminGeek.Siem.Ingest.IngestOptions { FlushInterval = TimeSpan.FromMilliseconds(50) }),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DreaminGeek.Siem.Ingest.IngestPipeline>.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await pipeline.StartAsync(cts.Token);
        var line = """<133>1 2026-11-12T05:04:43.100000+00:00 edge-proxy traefik-access - - - {"ClientHost":"216.160.83.56","ClientPort":"62848","DownstreamStatus":200,"RequestHost":"rmm-console.example.com","RequestMethod":"GET","RequestPath":"/healthz","RouterName":"17-rmm-console-example-router@http","StartUTC":"2026-11-12T05:04:22.599158061Z"}""";
        await pipeline.EnqueueAsync("dg", [new RawEnvelope(DateTimeOffset.UtcNow, "syslog-tcp", "127.0.0.1", line)], cts.Token);
        while (sink.Events.IsEmpty && !cts.IsCancellationRequested)
        {
            await Task.Delay(20, cts.Token);
        }
        await pipeline.StopAsync(CancellationToken.None);

        var e = Assert.Single(sink.Events);
        Assert.Equal("traefik.access", e.EventDataset);
        Assert.Equal("US", e.Fields["source.geo.country_iso_code"]);
        Assert.Equal("Milton", e.Fields["source.geo.city_name"]);
        Assert.Equal("64500", e.Fields["source.as.number"]);
    }
}
