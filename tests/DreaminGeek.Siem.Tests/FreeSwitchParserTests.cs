using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;

namespace DreaminGeek.Siem.Tests;

public sealed class FreeSwitchParserTests
{
    private static readonly ParserRegistry Registry = new([new AsteriskParser(), new FreeSwitchParser(), new SyslogParser()]);

    // pbx01 runs in UTC; the agent's header says so.
    private const string Header = "<14>1 2026-11-12T08:03:08.000000+00:00 pbx01 freeswitch - - - ";

    private static LogEvent Parse(string line) =>
        Registry.Parse(new RawEnvelope(new DateTimeOffset(2026, 11, 12, 8, 3, 8, TimeSpan.Zero), "file:/var/log/freeswitch/freeswitch.log", null, Header + line), "dg");

    [Fact]
    public void Call_lines_carry_the_uuid_channel_and_cause()
    {
        var e = Parse("65243b59-47f4-4693-8435-178b735e54d2 2026-11-10 18:53:39.395484 96.73% [DEBUG] mod_sofia.c:469 Channel sofia/external/2125550100@203.0.113.29 hanging up, cause: NORMAL_CLEARING");
        Assert.Equal(FreeSwitchParser.CallDataset, e.EventDataset);
        Assert.Equal("hangup", e.EventAction);
        Assert.Equal("success", e.EventOutcome);
        Assert.Equal("NORMAL_CLEARING", e.Fields["freeswitch.hangup_cause"]);
        Assert.Equal("65243b59-47f4-4693-8435-178b735e54d2", e.Fields["freeswitch.uuid"]);
        Assert.Equal("external", e.Fields["freeswitch.profile"]);
        Assert.Equal("2125550100", e.Fields["freeswitch.channel_user"]);
        Assert.Equal("203.0.113.29", e.Fields["freeswitch.channel_host"]);
        Assert.Equal(string.Empty, e.UserName); // a trunk leg's "user" is a phone number
        Assert.Equal("96.73", e.Fields["freeswitch.cpu_idle_pct"]);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 18, 53, 39, 395, TimeSpan.Zero).AddTicks(4840), e.Timestamp);
        Assert.Equal("pbx01", e.HostName);
        Assert.Equal("debug", e.LogLevel);

        var hangup = Parse("65243b59-47f4-4693-8435-178b735e54d2 2026-11-10 18:53:39.395484 96.73% [NOTICE] sofia.c:1065 Hangup sofia/internal/100@office.pbx.example.com [CS_EXECUTE] [NO_ROUTE_DESTINATION]");
        Assert.Equal("failure", hangup.EventOutcome);
        Assert.Equal("CS_EXECUTE", hangup.Fields["freeswitch.channel_state"]);
        Assert.Equal("100", hangup.UserName);

        var created = Parse("2026-11-10 18:50:01.115484 97.00% [NOTICE] switch_channel.c:1142 New Channel sofia/internal/100@office.pbx.example.com [65243b59-47f4-4693-8435-178b735e54d2]");
        Assert.Equal("new-channel", created.EventAction);
        Assert.Equal("65243b59-47f4-4693-8435-178b735e54d2", created.Fields["freeswitch.uuid"]);

        var answered = Parse("65243b59-47f4-4693-8435-178b735e54d2 2026-11-10 18:50:05.115484 97.00% [NOTICE] switch_channel.c:3993 Channel [sofia/internal/100@office.pbx.example.com] has been answered");
        Assert.Equal("answered", answered.EventAction);
    }

    [Fact]
    public void State_machine_chatter_is_plain_log_with_the_channel()
    {
        var e = Parse("65243b59-47f4-4693-8435-178b735e54d2 2026-11-10 18:53:39.395484 96.73% [DEBUG] switch_core_state_machine.c:844 (sofia/external/2125550100@203.0.113.29) Callstate Change ACTIVE -> HANGUP");
        Assert.Equal(FreeSwitchParser.LogDataset, e.EventDataset);
        Assert.Equal("sofia/external/2125550100@203.0.113.29", e.Fields["freeswitch.channel"]);
        Assert.Equal("switch_core_state_machine.c", e.Fields["log.origin.file.name"]);
        Assert.Equal("844", e.Fields["log.origin.file.line"]);

        var noUuid = Parse("2026-11-10 19:53:44.975489 97.27% [INFO] mod_enum.c:884 ENUM Reloaded");
        Assert.Equal("ENUM Reloaded", noUuid.Message);
        Assert.Equal("informational", noUuid.LogLevel);
        Assert.False(noUuid.Fields.ContainsKey("freeswitch.uuid"));

        var busy = Parse("2026-11-12 08:03:07.375496 96.77% [WARNING] switch_core_db.c:92 SQLite is BUSY, sane=299 [select nonce,last_nc from sip_authentication where nonce='6b1ac85e' and last_nc < 1442]");
        Assert.Equal("warning", busy.LogLevel);
        Assert.Equal("failure", busy.EventOutcome);

        var vm = Parse("2026-11-10 20:21:24.535484 95.83% [NOTICE] switch_cpp.cpp:1466 [voicemail] mailbox: 100@office.pbx.example.com messages: no new messages");
        Assert.Equal("[voicemail] mailbox: 100@office.pbx.example.com messages: no new messages", vm.Message);
    }

    [Fact]
    public void Auth_failures_and_unknown_users_are_security_events()
    {
        var e = Parse("2026-11-12 08:03:07.375496 96.77% [WARNING] sofia_reg.c:1854 SIP auth failure (REGISTER) on sofia profile 'internal' for [100@office.pbx.example.com] from ip 203.0.113.50");
        Assert.Equal(FreeSwitchParser.SecurityDataset, e.EventDataset);
        Assert.Equal("auth-failed", e.EventAction);
        Assert.Equal("failure", e.EventOutcome);
        Assert.Equal("100", e.UserName);
        Assert.Equal("office.pbx.example.com", e.Fields["sip.domain"]);
        Assert.Equal("203.0.113.50", e.SourceIp);
        Assert.Equal("REGISTER", e.Fields["sip.method"]);
        Assert.Equal("internal", e.Fields["freeswitch.profile"]);

        var scanner = Parse("2026-11-12 08:03:07.375496 96.77% [WARNING] sofia_reg.c:3203 Can't find user [1001@198.51.100.243] from 203.0.113.95\n" +
            "You must define a domain called '198.51.100.243' in your directory and add a user with the id=\"1001\" attribute\n" +
            "and you must configure your device to use the proper domain in it's authentication credentials.");
        Assert.Equal("unknown-account", scanner.EventAction);
        Assert.Equal("1001", scanner.UserName);
        Assert.Equal("203.0.113.95", scanner.SourceIp);
        Assert.Equal("Can't find user [1001@198.51.100.243] from 203.0.113.95", scanner.Message);

        var acl = Parse("2026-11-12 08:03:07.375496 96.77% [WARNING] sofia.c:10495 IP 198.51.100.9 Rejected by acl \"providers\"");
        Assert.Equal("acl-denied", acl.EventAction);
        Assert.Equal("providers", acl.Fields["freeswitch.acl"]);

        var fallback = Parse("2026-11-12 08:03:07.375496 96.77% [DEBUG] sofia.c:2353 IP 198.51.100.240 Rejected by acl \"domains\". Falling back to Digest auth.");
        Assert.Equal("acl-digest-fallback", fallback.EventAction);
        Assert.Equal("unknown", fallback.EventOutcome);
    }

    [Fact]
    public void Registrations_find_the_phone_behind_nat()
    {
        var e = Parse("2026-11-12 01:24:24.935491 96.77% [DEBUG] sofia_reg.c:2069 Register:\n" +
            "From:    [100@office.pbx.example.com]\n" +
            "Contact: [\"Front Desk\" <sip:100@10.1.1.160:7057;transport=tcp;fs_nat=yes;fs_path=sip%3A100%40198.51.100.240%3A7057%3Btransport%3Dtcp>]\n" +
            "Expires: [3600]");
        Assert.Equal(FreeSwitchParser.RegistrationDataset, e.EventDataset);
        Assert.Equal("registered", e.EventAction);
        Assert.Equal("100", e.UserName);
        Assert.Equal("198.51.100.240", e.SourceIp);
        Assert.Equal("10.1.1.160", e.Fields["freeswitch.contact_private_ip"]);
        Assert.Equal("3600", e.Fields["freeswitch.expires"]);
        Assert.Equal("Registered 100@office.pbx.example.com from 198.51.100.240", e.Message);

        var challenge = Parse("2026-11-12 01:24:24.935491 96.77% [DEBUG] sofia_reg.c:1748 SIP auth challenge (REGISTER) on sofia profile 'internal' for [100@office.pbx.example.com] from ip 198.51.100.240");
        Assert.Equal(FreeSwitchParser.RegistrationDataset, challenge.EventDataset);
        Assert.Equal("auth-challenge", challenge.EventAction);
    }

    [Fact]
    public void Trunk_problems_are_registration_failures()
    {
        var ping = Parse("2026-11-12 01:24:24.935491 96.77% [WARNING] sofia_reg.c:478 Ping failed voipms with code 503 - count 1/2/2, state DOWN");
        Assert.Equal("gateway-ping-failed", ping.EventAction);
        Assert.Equal("voipms", ping.Fields["freeswitch.gateway"]);
        Assert.Equal("down", ping.Fields["freeswitch.gateway_state"]);
        Assert.Equal("503", ping.Fields["sip.status_code"]);

        var reg = Parse("2026-11-12 01:24:24.935491 96.77% [ERR] sofia_reg.c:551 voipms Failed Registration with status 403 [403]. failure #2");
        Assert.Equal("gateway-registration-failed", reg.EventAction);
        Assert.Equal("403", reg.Fields["sip.status_code"]);
        Assert.Equal("error", reg.LogLevel);
    }

    [Fact]
    public void Local_time_uses_the_agents_offset()
    {
        var central = Registry.Parse(new RawEnvelope(DateTimeOffset.UtcNow, "file:/var/log/freeswitch/freeswitch.log", null,
            "<14>1 2026-11-12T02:03:08.000000-06:00 pbx freeswitch - - - 2026-11-12 02:03:07.5 97.00% [INFO] mod_enum.c:884 ENUM Reloaded"), "dg");
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 8, 3, 7, 500, TimeSpan.Zero), central.Timestamp);
        Assert.Equal("-06:00", central.Fields["event.timezone"]);
    }

    [Fact]
    public void Asterisk_lines_still_go_to_the_asterisk_parser()
    {
        var e = Parse("[2026-11-12 02:03:07] VERBOSE[1554] res_pjsip/pjsip_configuration.c: Endpoint 114 is now Reachable");
        Assert.Equal(AsteriskParser.RegistrationDataset, e.EventDataset);
    }
}
