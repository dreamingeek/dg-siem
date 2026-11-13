using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;

namespace DreaminGeek.Siem.Tests;

public sealed class AsteriskParserTests
{
    private static readonly ParserRegistry Registry = new([new AsteriskParser(), new TraefikParser(), new SyslogParser()]);

    // When the agent read the line: 10:31:17 in Central time (-06:00).
    private const string AgentHeader = "<14>1 2026-11-12T10:31:17.250000-06:00 acme-pbx full - - - ";

    private static LogEvent Parse(string message, DateTimeOffset? receivedAt = null) =>
        Registry.Parse(new RawEnvelope(receivedAt ?? new DateTimeOffset(2026, 11, 12, 16, 31, 17, TimeSpan.Zero), "file:/var/log/asterisk/full", null, message), "acme");

    private static string Packet(params string[] lines) => AgentHeader + string.Join('\n', lines);

    [Fact]
    public void Transmitted_responses_are_sip_packets()
    {
        var e = Parse(Packet(
            "[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip_logger.c: <--- Transmitting SIP response (430 bytes) to UDP:216.160.83.56:9505 --->",
            "SIP/2.0 200 OK",
            "Via: SIP/2.0/UDP 10.10.3.209:5060;rport=9505;received=216.160.83.56;branch=z9hG4bK-24fa852f",
            "Call-ID: 1bc9d842-bcc27283@10.10.3.209",
            "From: \"114\" <sip:114@pbx.example.com>;tag=a0fea4a615b8a0o0",
            "To: \"114\" <sip:114@pbx.example.com>;tag=z9hG4bK-24fa852f",
            "CSeq: 24854 REGISTER",
            "Date: Thu, 12 Nov 2026 16:31:16 GMT",
            "Contact: <sip:114@10.10.3.209:5060>;expires=59",
            "Server: FPBX-203.0.113.17(22.11.0)",
            "Content-Length:  0"));

        Assert.Equal(AsteriskParser.SipDataset, e.EventDataset);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 16, 31, 16, TimeSpan.Zero), e.Timestamp); // local 10:31:16 at -06:00
        Assert.Equal("-06:00", e.Fields["event.timezone"]);
        Assert.Equal("acme-pbx", e.HostName);
        Assert.Equal("response", e.EventAction);
        Assert.Equal("success", e.EventOutcome);
        Assert.Equal("200", e.Fields["sip.status_code"]);
        Assert.Equal("REGISTER", e.Fields["sip.method"]);
        Assert.Equal("1bc9d842-bcc27283@10.10.3.209", e.Fields["sip.call_id"]);
        Assert.Equal("114", e.UserName);
        Assert.Equal("pbx.example.com", e.Fields["sip.from.host"]);
        Assert.Equal("216.160.83.56", e.DestinationIp);
        Assert.Equal(9505, e.DestinationPort);
        Assert.Equal("udp", e.NetworkTransport);
        Assert.Equal("sip", e.NetworkProtocol);
        Assert.Equal("outbound", e.Fields["network.direction"]);
        Assert.Equal("Sent 200 OK (REGISTER) to 216.160.83.56:9505", e.Message);
        Assert.Contains("CSeq: 24854 REGISTER", e.Raw, StringComparison.Ordinal);
    }

    [Fact]
    public void Requests_and_received_responses()
    {
        var notify = Parse(Packet(
            "[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip_logger.c: <--- Transmitting SIP request (633 bytes) to UDP:216.160.83.56:9505 --->",
            "NOTIFY sip:114@216.160.83.56:9505 SIP/2.0",
            "Via: SIP/2.0/UDP 203.0.113.136:5060;rport;branch=z9hG4bKPjfc0dd2aa-b065-4595-9cde-f574ee52d043",
            "From: <sip:114@203.0.113.136>;tag=4432ab5b-4daf-4ff6-b178-637869dd420c",
            "To: <sip:114@216.160.83.56>",
            "Call-ID: f1fcc408-659d-4a4b-835e-ae1ab7cabb78",
            "CSeq: 23977 NOTIFY",
            "Event: message-summary",
            "User-Agent: FPBX-203.0.113.17(22.11.0)",
            "Content-Length:    48",
            "",
            "Messages-Waiting: no",
            "Voice-Message: 0/0 (0/0)"));
        Assert.Equal("notify", notify.EventAction);
        Assert.Equal("NOTIFY", notify.Fields["sip.method"]);
        Assert.Equal("sip:114@216.160.83.56:9505", notify.Fields["sip.request_uri"]);
        Assert.Equal("Sent NOTIFY sip:114@216.160.83.56:9505 to 216.160.83.56:9505", notify.Message);
        Assert.False(notify.Fields.ContainsKey("Messages-Waiting")); // the body isn't a header

        var phone = Parse(Packet(
            "[2026-11-12 10:31:16] VERBOSE[1559] res_pjsip_logger.c: <--- Received SIP response (347 bytes) from UDP:216.160.83.56:9505 --->",
            "SIP/2.0 200 OK",
            "To: <sip:114@216.160.83.56>;tag=da42a9f4f5078590i0",
            "From: <sip:114@203.0.113.136>;tag=4432ab5b-4daf-4ff6-b178-637869dd420c",
            "Call-ID: f1fcc408-659d-4a4b-835e-ae1ab7cabb78",
            "CSeq: 23977 NOTIFY",
            "Server: Cisco/SPA514G-7.6.2e",
            "Content-Length: 0"));
        Assert.Equal("inbound", phone.Fields["network.direction"]);
        Assert.Equal("216.160.83.56", phone.SourceIp);
        Assert.Equal("Cisco/SPA514G-7.6.2e", phone.Fields["user_agent.original"]);
        Assert.Equal("Received 200 OK (NOTIFY) from 216.160.83.56:9505", phone.Message);
    }

    [Fact]
    public void Register_requests_name_the_phone()
    {
        var e = Parse(Packet(
            "[2026-11-12 10:31:16] VERBOSE[1559] res_pjsip_logger.c: <--- Received SIP request (612 bytes) from UDP:216.160.83.56:9505 --->",
            "REGISTER sip:pbx.example.com SIP/2.0",
            "Via: SIP/2.0/UDP 10.10.3.209:5060;branch=z9hG4bK-24fa852f",
            "From: \"114\" <sip:114@pbx.example.com>;tag=a0fea4a615b8a0o0",
            "To: \"114\" <sip:114@pbx.example.com>",
            "Call-ID: 1bc9d842-bcc27283@10.10.3.209",
            "CSeq: 24854 REGISTER",
            "Contact: \"114\" <sip:114@10.10.3.209:5060>;expires=60",
            "User-Agent: Cisco/SPA514G-7.6.2e",
            "Content-Length: 0"));
        Assert.Equal("register", e.EventAction);
        Assert.Equal("114", e.UserName);
        Assert.Equal("114", e.Fields["sip.from.display"]);
        Assert.Equal("216.160.83.56", e.SourceIp);
        Assert.Equal("Cisco/SPA514G-7.6.2e", e.Fields["user_agent.original"]);
        Assert.Equal("SIP/2.0/UDP 10.10.3.209:5060;branch=z9hG4bK-24fa852f", e.Fields["sip.via"]);
    }

    [Fact]
    public void Failed_registrations_are_security_events()
    {
        var e = Parse(AgentHeader + "[2026-11-12 10:31:16] NOTICE[1559] res_pjsip/pjsip_distributor.c: Request 'REGISTER' from '\"114\" <sip:114@pbx.example.com>' failed for '203.0.113.50:5072' (callid: abc123) - Failed to authenticate");
        Assert.Equal(AsteriskParser.SecurityDataset, e.EventDataset);
        Assert.Equal("auth-failed", e.EventAction);
        Assert.Equal("failure", e.EventOutcome);
        Assert.Equal("114", e.UserName);
        Assert.Equal("203.0.113.50", e.SourceIp);
        Assert.Equal(5072, e.SourcePort);
        Assert.Equal("REGISTER", e.Fields["sip.method"]);
        Assert.Equal("abc123", e.Fields["sip.call_id"]);
        Assert.Equal("notice", e.LogLevel);

        var scanner = Parse(AgentHeader + "[2026-11-12 10:31:16] NOTICE[1559] res_pjsip/pjsip_distributor.c: Request 'INVITE' from '<sip:100@203.0.113.136>' failed for '198.51.100.9:5060' (callid: x) - No matching endpoint found");
        Assert.Equal("unknown-account", scanner.EventAction);
        Assert.Equal("100", scanner.UserName);

        var chanSip = Parse(AgentHeader + "[2026-11-12 10:31:16] NOTICE[1559] chan_sip.c: Registration from '\"101\"<sip:101@pbx.example.com>' failed for '198.51.100.9:5060' - Wrong password");
        Assert.Equal("auth-failed", chanSip.EventAction);
        Assert.Equal("101", chanSip.UserName);
    }

    [Fact]
    public void Security_log_events_use_their_own_time_and_drop_hashes()
    {
        var e = Parse(AgentHeader + "[2026-11-12 10:31:16] SECURITY[1559] res_security_log.c: SecurityEvent=\"ChallengeResponseFailed\",EventTV=\"2026-11-12T10:31:16.482911-0600\",Severity=\"Error\",Service=\"PJSIP\",EventVersion=\"1\",AccountID=\"114\",SessionID=\"1bc9d842-bcc27283@10.10.3.209\",LocalAddress=\"IPV4/UDP/203.0.113.136/5060\",RemoteAddress=\"IPV4/UDP/203.0.113.50/5072\",Challenge=\"1715100000/abc\",Response=\"deadbeef\",ExpectedResponse=\"\"");
        Assert.Equal(AsteriskParser.SecurityDataset, e.EventDataset);
        Assert.Equal("challenge-response-failed", e.EventAction);
        Assert.Equal("failure", e.EventOutcome);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 16, 31, 16, 482, TimeSpan.Zero).AddTicks(9110), e.Timestamp);
        Assert.Equal("114", e.UserName);
        Assert.Equal("203.0.113.50", e.SourceIp);
        Assert.Equal("203.0.113.136", e.DestinationIp);
        Assert.Equal("udp", e.NetworkTransport);
        Assert.Equal("PJSIP", e.Fields["asterisk.security.service"]);
        Assert.Equal("Error", e.Fields["asterisk.security.severity"]);
        Assert.DoesNotContain(e.Fields.Keys, k => k.Contains("challenge", StringComparison.Ordinal) || k.Contains("response", StringComparison.Ordinal));
        Assert.Equal("ChallengeResponseFailed for 114 from 203.0.113.50", e.Message);

        var ok = Parse(AgentHeader + "[2026-11-12 10:31:16] SECURITY[1559] res_security_log.c: SecurityEvent=\"SuccessfulAuth\",EventTV=\"2026-11-12T10:31:16.5-0600\",Severity=\"Informational\",Service=\"PJSIP\",AccountID=\"114\",RemoteAddress=\"IPV4/UDP/216.160.83.56/9505\",UsingPassword=\"1\"");
        Assert.Equal("successful-auth", ok.EventAction);
        Assert.Equal("success", ok.EventOutcome);
        Assert.Equal("1", ok.Fields["asterisk.security.using_password"]);
    }

    [Fact]
    public void Registrations_and_reachability()
    {
        var added = Parse(AgentHeader + "[2026-11-12 10:31:16] VERBOSE[1559] res_pjsip_registrar.c: Added contact 'sip:114@216.160.83.56:9505;x-ast-orig-host=10.10.3.209:5060' to AOR '114' with expiration of 60 seconds");
        Assert.Equal(AsteriskParser.RegistrationDataset, added.EventDataset);
        Assert.Equal("registered", added.EventAction);
        Assert.Equal("114", added.UserName);
        Assert.Equal("216.160.83.56", added.SourceIp);
        Assert.Equal("10.10.3.209", added.Fields["asterisk.contact_private_ip"]);
        Assert.Equal("60", added.Fields["asterisk.expires"]);

        var removed = Parse(AgentHeader + "[2026-11-12 10:31:16] VERBOSE[1559] res_pjsip_registrar.c: Removed contact 'sip:114@216.160.83.56:9505' from AOR '114' due to expiration");
        Assert.Equal("unregistered", removed.EventAction);
        Assert.Equal("expiration", removed.Fields["asterisk.reason"]);

        var down = Parse(AgentHeader + "[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip/pjsip_configuration.c: Endpoint 114 is now Unreachable");
        Assert.Equal("endpoint-unreachable", down.EventAction);
        Assert.Equal("failure", down.EventOutcome);

        var rtt = Parse(AgentHeader + "[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip/pjsip_options.c: Contact 114/sip:114@216.160.83.56:9505;x-ast-orig-host=10.10.3.209:5060 is now Reachable.  RTT: 34.162 msec");
        Assert.Equal("contact-reachable", rtt.EventAction);
        Assert.Equal("34.162", rtt.Fields["asterisk.rtt_ms"]);
    }

    [Fact]
    public void Dialplan_and_dial_progress()
    {
        var x = Parse(AgentHeader + "[2026-11-12 10:31:16] VERBOSE[2210][C-0000001a] pbx.c: Executing [115@from-internal:1] Macro(\"PJSIP/114-00000012\", \"exten-vm,novm,115,0,0,0\") in new stack");
        Assert.Equal(AsteriskParser.CallDataset, x.EventDataset);
        Assert.Equal("C-0000001a", x.Fields["asterisk.call_id"]);
        Assert.Equal("from-internal", x.Fields["asterisk.context"]);
        Assert.Equal("115", x.Fields["asterisk.extension"]);
        Assert.Equal("Macro", x.Fields["asterisk.application"]);
        Assert.Equal("114", x.UserName);

        var answered = Parse(AgentHeader + "[2026-11-12 10:31:16] VERBOSE[2210][C-0000001a] app_dial.c:     -- PJSIP/115-00000013 answered PJSIP/114-00000012");
        Assert.Equal("answered", answered.EventAction);
        Assert.Equal("115", answered.UserName);
        Assert.Equal("114", answered.Fields["asterisk.peer_channel_endpoint"]);
        Assert.Equal("PJSIP/115-00000013 answered PJSIP/114-00000012", answered.Message);
    }

    [Fact]
    public void Other_lines_and_other_carriers()
    {
        // Anything else is still an Asterisk event with its level and source file.
        var warn = Parse(AgentHeader + "[2026-11-12 10:31:16] WARNING[1600] res_pjsip_outbound_registration.c: No response received from 'sip:sip.example-provider.net:5060' on registration attempt to 'sip:123456@sip.example-provider.net:5060', retrying in '60'");
        Assert.Equal(AsteriskParser.LogDataset, warn.EventDataset);
        Assert.Equal("warning", warn.LogLevel);
        Assert.Equal("failure", warn.EventOutcome);
        Assert.Equal("res_pjsip_outbound_registration.c", warn.Fields["log.origin.file.name"]);

        // Asterisk's own syslog channel: "LEVEL[lwp]: file:line in func: message", no bracketed time.
        var syslog = Parse("<29>Nov 12 10:31:16 acme-pbx asterisk[1200]: NOTICE[1559]: res_pjsip/pjsip_distributor.c:676 in log_failed_request: Request 'REGISTER' from '<sip:200@x>' failed for '198.51.100.9:5060' (callid: y) - Failed to authenticate");
        Assert.Equal("auth-failed", syslog.EventAction);
        Assert.Equal("676", syslog.Fields["log.origin.file.line"]);
        Assert.Equal("log_failed_request", syslog.Fields["log.origin.function"]);

        // A bare line (rsyslog without a template) works out the offset from when it arrived.
        var bare = Parse("[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip/pjsip_configuration.c: Endpoint 114 is now Reachable",
            new DateTimeOffset(2026, 11, 12, 16, 31, 17, TimeSpan.Zero));
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 16, 31, 16, TimeSpan.Zero), bare.Timestamp);
    }

    [Fact]
    public void Non_asterisk_lines_are_left_alone()
    {
        var e = Parse("<14>1 2026-11-12T10:31:17-06:00 host app - - - WARNING[ this is not asterisk");
        Assert.Equal("syslog", e.EventDataset);
    }
}
