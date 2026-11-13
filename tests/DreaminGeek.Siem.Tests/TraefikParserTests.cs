using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;

namespace DreaminGeek.Siem.Tests;

public class TraefikParserTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 12, 5, 5, 0, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new TraefikParser(), new UnifiParser(), new SyslogParser()]);

    // As rsyslog on edge-proxy forwards them (imfile tag traefik-access, RFC 5424 template, local0.notice).
    private const string Header = "<133>1 2026-11-12T05:04:43.100000+00:00 edge-proxy traefik-access - - - ";

    private const string Proxied =
        """{"ClientAddr":"198.51.100.24:49835","ClientHost":"198.51.100.24","ClientPort":"49835","ClientUsername":"-","DownstreamContentSize":4326,"DownstreamStatus":200,"Duration":287504981,"OriginContentSize":4326,"OriginDuration":275155297,"OriginStatus":200,"Overhead":12349684,"RequestAddr":"office.backup.example.com","RequestContentSize":178,"RequestCount":4646,"RequestHost":"office.backup.example.com","RequestMethod":"POST","RequestPath":"/api/v1/user/get-profile-and-hash","RequestPort":"-","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,"RouterName":"14-office-backup-example-router@http","ServiceAddr":"100.64.0.4:62959","ServiceName":"14-office-backup-example-service@http","ServiceURL":"http://100.64.0.4:62959","StartLocal":"2026-11-12T05:04:42.879906106Z","StartUTC":"2026-11-12T05:04:42.879906106Z","TLSCipher":"TLS_AES_128_GCM_SHA256","TLSVersion":"1.3","entryPointName":"websecure","level":"info","msg":"","request_User-Agent":"CometBackup/26.11.1","time":"2026-11-12T05:04:43Z"}""";

    private const string Scanner =
        """{"ClientAddr":"198.51.100.149:11820","ClientHost":"198.51.100.149","ClientPort":"11820","ClientUsername":"-","DownstreamContentSize":19,"DownstreamStatus":404,"Duration":130232,"GzipRatio":0,"OriginContentSize":0,"OriginDuration":0,"OriginStatus":0,"Overhead":130232,"RequestAddr":"www.example.org","RequestContentSize":0,"RequestCount":369,"RequestHost":"www.example.org","RequestMethod":"GET","RequestPath":"/wp-admin/install.php?step=1","RequestPort":"-","RequestProtocol":"HTTP/1.1","RequestScheme":"http","RetryAttempts":0,"StartLocal":"2026-10-31T19:16:22.202881372Z","StartUTC":"2026-10-31T19:16:22.202881372Z","entryPointName":"web","level":"info","msg":"","request_User-Agent":"http://www.example.org/wp-admin/install.php?step=1","time":"2026-10-31T19:16:22Z"}""";

    private LogEvent Parse(string line) => _registry.Parse(new RawEnvelope(Received, "syslog-tcp", "127.0.0.1", line), "dg");

    [Fact]
    public void ProxiedRequestMapsToEcs()
    {
        var e = Parse(Header + Proxied);

        Assert.Equal("traefik.access", e.EventDataset);
        Assert.Equal("traefik", e.EventModule);
        Assert.Equal("proxied", e.EventAction);
        Assert.Equal("success", e.EventOutcome);
        Assert.Equal("informational", e.LogLevel);
        Assert.Equal("edge-proxy", e.HostName);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 5, 4, 42, 879, TimeSpan.Zero), e.Timestamp, TimeSpan.FromMilliseconds(1));
        Assert.Equal("198.51.100.24", e.SourceIp);
        Assert.Equal(49835, e.SourcePort);
        Assert.Equal("http", e.NetworkProtocol);
        Assert.Equal("POST office.backup.example.com/api/v1/user/get-profile-and-hash 200 287.5 ms", e.Message);

        var f = e.Fields;
        Assert.Equal("POST", f["http.request.method"]);
        Assert.Equal("200", f["http.response.status_code"]);
        Assert.Equal("2.0", f["http.version"]);
        Assert.Equal("4326", f["http.response.body.bytes"]);
        Assert.Equal("office.backup.example.com", f["url.domain"]);
        Assert.Equal("/api/v1/user/get-profile-and-hash", f["url.path"]);
        Assert.Equal("https", f["url.scheme"]);
        Assert.Equal("CometBackup/26.11.1", f["user_agent.original"]);
        Assert.Equal("287504981", f["event.duration"]);
        Assert.Equal("1.3", f["tls.version"]);
        Assert.Equal("websecure", f["traefik.entrypoint"]);
        Assert.Equal("14-office-backup-example-router@http", f["traefik.router.name"]);
        Assert.Equal("office-backup-example", f["pangolin.resource.name"]);
        Assert.Equal("traefik-access", f["process.name"]);
        Assert.False(f.ContainsKey("url.query"));
    }

    [Fact]
    public void UnroutedScannerIsAFailedWarning()
    {
        var e = Parse(Header + Scanner);

        Assert.Equal("unrouted", e.EventAction);
        Assert.Equal("failure", e.EventOutcome);
        Assert.Equal("warning", e.LogLevel);
        Assert.Equal("404", e.Fields["http.response.status_code"]);
        Assert.Equal("/wp-admin/install.php", e.Fields["url.path"]);
        Assert.Equal("step=1", e.Fields["url.query"]);
        Assert.Equal("/wp-admin/install.php?step=1", e.Fields["url.original"]);
        Assert.False(e.Fields.ContainsKey("traefik.router.name"));
        Assert.False(e.Fields.ContainsKey("traefik.origin.status_code"));
        Assert.False(e.Fields.ContainsKey("tls.version"));
    }

    [Fact]
    public void BareJsonLinesParseToo()
    {
        var e = Parse(Scanner);
        Assert.Equal("traefik.access", e.EventDataset);
        Assert.Equal(new DateTimeOffset(2026, 10, 31, 19, 16, 22, 202, TimeSpan.Zero), e.Timestamp, TimeSpan.FromMilliseconds(1));
    }

    [Fact]
    public void BrokenJsonFallsBackToSyslog()
    {
        var e = Parse(Header + """{"DownstreamStatus":500,"RequestHost":"x""");
        Assert.Equal("syslog", e.EventDataset);
    }

    [Theory]
    [InlineData("17-rmm-console-example-router@http", "rmm-console-example")]
    [InlineData("api-router@internal", null)]
    [InlineData("websecure-to-web@file", null)]
    [InlineData(null, null)]
    public void PangolinResourceFromRouterName(string? router, string? expected) =>
        Assert.Equal(expected, TraefikParser.PangolinResource(router));
}
