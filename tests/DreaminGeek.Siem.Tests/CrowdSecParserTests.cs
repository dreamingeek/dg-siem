using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;

namespace DreaminGeek.Siem.Tests;

public class CrowdSecParserTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 12, 5, 40, 0, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new TraefikParser(), new AuthentikParser(), new CrowdSecParser(), new UnifiParser(), new SyslogParser()]);

    // Docker's syslog driver (tag: crowdsec) → rsyslog on edge-proxy → RFC 5424.
    private const string Header = "<30>1 2026-11-12T05:40:01.000000+00:00 edge-proxy crowdsec 812 - - ";

    private LogEvent Parse(string body) => _registry.Parse(new RawEnvelope(Received, "syslog-tcp", "127.0.0.1", Header + body), "dg");

    [Fact]
    public void BanDecision()
    {
        var e = Parse("""time="2026-11-12T05:40:00Z" level=info msg="(5c1e8f0a2b/crowdsec) crowdsecurity/http-probing by ip 45.148.10.12 (NL/48090) : 4h ban on Ip 45.148.10.12" """);

        Assert.Equal("crowdsec.decision", e.EventDataset);
        Assert.Equal("ban", e.EventAction);
        Assert.Equal("45.148.10.12", e.SourceIp);
        Assert.Equal("warning", e.LogLevel);
        Assert.Equal("edge-proxy", e.HostName);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 5, 40, 0, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("crowdsecurity/http-probing", e.Fields["rule.name"]);
        Assert.Equal("4h", e.Fields["crowdsec.decision.duration"]);
        Assert.Equal("5c1e8f0a2b/crowdsec", e.Fields["crowdsec.origin"]);
        Assert.Equal("NL", e.Fields["source.geo.country_iso_code"]);
        Assert.Equal("48090", e.Fields["source.as.number"]);
        Assert.Equal("alert", e.Fields["event.kind"]);
        Assert.Equal("4h ban on 45.148.10.12 for crowdsecurity/http-probing (NL)", e.Message);
    }

    [Fact]
    public void MultiDecisionAndSimulatedVariants()
    {
        var e = Parse("""time="2026-11-12T05:40:00Z" level=info msg="(m1/crowdsec) crowdsecurity/ssh-bf for 1/2 decisions by ip 203.0.113.7 (CN/4134) : (simulated decision)3h59m58.5s ban on Ip 203.0.113.7" """);
        Assert.Equal("crowdsec.decision", e.EventDataset);
        Assert.Equal("crowdsecurity/ssh-bf", e.Fields["rule.name"]);
        Assert.Equal("3h59m58.5s", e.Fields["crowdsec.decision.duration"]);
        Assert.Equal("true", e.Fields["crowdsec.simulated"]);
    }

    [Fact]
    public void ScenarioOverflow()
    {
        var e = Parse("""time="2026-11-12T05:39:59Z" level=info msg="Ip 45.148.10.12 performed 'crowdsecurity/http-probing' (11 events over 2.172742s) at 2026-11-12 05:39:59.8 +0000 UTC" """);
        Assert.Equal("crowdsec.alert", e.EventDataset);
        Assert.Equal("scenario_triggered", e.EventAction);
        Assert.Equal("45.148.10.12", e.SourceIp);
        Assert.Equal("crowdsecurity/http-probing", e.Fields["rule.name"]);
        Assert.Equal("11", e.Fields["crowdsec.event_count"]);
    }

    // Sample lines from a CrowdSec host.
    [Fact]
    public void BouncerPollingIsLapiNoise()
    {
        var e = Parse("""time="2026-11-12T05:33:51Z" level=info msg="172.18.0.4 - [Thu, 12 Nov 2026 05:33:51 UTC] \"GET /v1/decisions/stream?startup=false HTTP/1.1 200 6.174207ms \"Crowdsec-Bouncer-Traefik-Plugin/v1.8.1\" \"" module=lapi""");
        Assert.Equal("crowdsec.lapi", e.EventDataset);
        Assert.Equal("172.18.0.4", e.SourceIp);
        Assert.Equal("/v1/decisions/stream", e.Fields["url.path"]);
        Assert.Equal("200", e.Fields["http.response.status_code"]);
        Assert.Equal("Crowdsec-Bouncer-Traefik-Plugin/v1.8.1", e.Fields["user_agent.original"]);
        Assert.Equal("lapi", e.Fields["crowdsec.module"]);
    }

    [Fact]
    public void AllowlistedWafRequest()
    {
        var e = Parse("""time="2026-11-12T05:35:00Z" level=info msg="216.160.83.56 is allowlisted by 216.160.83.56 from dg-trusted, skipping WAF processing" module=acquisition.appsec name=appsec request_uuid=5cc0c334-acda-4c0c-a2fd-a0c0362fa519 runner_uuid=c83bdb5b-122c-4469-80e1-a029aeaf3517 type=appsec""");
        Assert.Equal("crowdsec.appsec", e.EventDataset);
        Assert.Equal("allowlisted", e.EventAction);
        Assert.Equal("216.160.83.56", e.SourceIp);
        Assert.Equal("dg-trusted", e.Fields["crowdsec.allowlist"]);
    }

    [Fact]
    public void OtherLinesAreGeneralLog()
    {
        var e = Parse("""time="2026-11-12T05:35:09Z" level=info msg="flushed 1/2697 alerts because they were created 168h0m0s ago or more" module=db""");
        Assert.Equal("crowdsec.log", e.EventDataset);
        Assert.Equal("flushed 1/2697 alerts because they were created 168h0m0s ago or more", e.Message);
    }

    [Fact]
    public void OtherLogrusAppsAreNotClaimed()
    {
        var e = _registry.Parse(new RawEnvelope(Received, "syslog-tcp", "10.0.0.5",
            """<30>1 2026-11-12T05:40:01Z web01 myapp 1 - - time="2026-11-12T05:40:00Z" level=info msg="started" """), "dg");
        Assert.Equal("syslog", e.EventDataset);
    }

    [Fact]
    public void LogfmtHandlesQuotesAndEscapes()
    {
        var kv = CrowdSecParser.Logfmt("""time="2026-11-12T05:35:00Z" level=warning msg="a \"quoted\" word" module=lapi bare""");
        Assert.Equal("warning", kv["level"]);
        Assert.Equal("a \"quoted\" word", kv["msg"]);
        Assert.Equal("lapi", kv["module"]);
    }
}
