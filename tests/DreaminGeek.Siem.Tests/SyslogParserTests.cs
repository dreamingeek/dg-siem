using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;

namespace DreaminGeek.Siem.Tests;

public class SyslogParserTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 11, 18, 0, 0, TimeSpan.Zero);
    private readonly SyslogParser _parser = new();

    private LogEvent Parse(string line, string? hint = null)
    {
        var env = new RawEnvelope(Received, "syslog-udp", "192.168.1.1", line, hint);
        Assert.True(_parser.CanParse(env));
        Assert.True(_parser.TryParse(env, "dg", out var evt));
        return evt!;
    }

    [Fact]
    public void Parses_rfc5424_with_structured_data()
    {
        var e = Parse("<165>1 2026-11-11T17:59:58.123Z gw01 sshd 4242 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\\]\"] Accepted password for jdoe");

        Assert.Equal("dg", e.TenantId);
        Assert.Equal(new DateTimeOffset(2026, 11, 11, 17, 59, 58, 123, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("gw01", e.HostName);
        Assert.Equal("notice", e.LogLevel);                 // 165 % 8 = 5
        Assert.Equal("20", e.Fields["log.syslog.facility.code"]); // 165 / 8 = 20 (local4)
        Assert.Equal("sshd", e.Fields["process.name"]);
        Assert.Equal("4242", e.Fields["process.pid"]);
        Assert.Equal("Accepted password for jdoe", e.Message);
        Assert.Equal("192.168.1.1", e.ObserverIp);
    }

    [Fact]
    public void Parses_rfc5424_with_nil_values()
    {
        var e = Parse("<14>1 - - - - - - hello");
        Assert.Equal(Received, e.Timestamp);
        Assert.Equal(string.Empty, e.HostName);
        Assert.Equal("hello", e.Message);
    }

    [Fact]
    public void Parses_rfc3164_with_tag_and_pid()
    {
        var e = Parse("<30>Nov 11 17:55:01 UDM-Pro dnsmasq[1234]: query[A] example.com from 10.0.0.5");

        Assert.Equal(new DateTimeOffset(2026, 11, 11, 17, 55, 1, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("UDM-Pro", e.HostName);
        Assert.Equal("dnsmasq", e.Fields["process.name"]);
        Assert.Equal("1234", e.Fields["process.pid"]);
        Assert.Equal("query[A] example.com from 10.0.0.5", e.Message);
        Assert.Equal("informational", e.LogLevel);
    }

    [Fact]
    public void Parses_rfc3164_single_digit_day()
    {
        var e = Parse("<13>Nov  1 08:00:00 host app: started");
        Assert.Equal(new DateTimeOffset(2026, 11, 1, 8, 0, 0, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("app", e.Fields["process.name"]);
        Assert.Equal("started", e.Message);
    }

    [Fact]
    public void Rfc3164_year_rolls_back_for_december_lines_received_in_january()
    {
        var env = new RawEnvelope(new DateTimeOffset(2027, 1, 1, 0, 0, 5, TimeSpan.Zero), "syslog-udp", null, "<13>Dec 31 23:59:59 host app: tick");
        Assert.True(_parser.TryParse(env, "dg", out var e));
        Assert.Equal(2026, e!.Timestamp.Year);
    }

    [Fact]
    public void Uses_dataset_hint_from_agent_config()
    {
        var e = Parse("<14>1 - - - - - - hello", hint: "unifi");
        Assert.Equal("unifi", e.EventDataset);
    }

    [Theory]
    [InlineData("no pri here")]
    [InlineData("<999>bad pri")]
    [InlineData("<>empty")]
    public void Rejects_non_syslog(string line)
    {
        var env = new RawEnvelope(Received, "syslog-udp", null, line);
        Assert.False(_parser.CanParse(env) && _parser.TryParse(env, "dg", out _));
    }
}
