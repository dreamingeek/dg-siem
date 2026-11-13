using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Formats;
using DreaminGeek.Siem.Parsers.Vendors;

namespace DreaminGeek.Siem.Tests;

public class UnifiParserTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 11, 18, 0, 0, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new UnifiParser(), new SyslogParser()]);

    private LogEvent Parse(string line, string? hint = null) =>
        _registry.Parse(new RawEnvelope(Received, "syslog-udp", "192.168.1.1", line, hint), "acme");

    [Fact]
    public void Cef_extension_handles_spaces_and_escapes()
    {
        var x = Cef.ParseExtension(@"msg=jdoe logged in from the web src=10.0.0.5 cs1=a\=b c\\d cs2=line1\nline2".AsSpan());
        Assert.Equal("jdoe logged in from the web", x["msg"]);
        Assert.Equal("10.0.0.5", x["src"]);
        Assert.Equal(@"a=b c\d", x["cs1"]);
        Assert.Equal("line1\nline2", x["cs2"]);
    }

    [Fact]
    public void Cef_header_handles_escaped_pipes()
    {
        Assert.True(Cef.TryParse(@"CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Name with \| pipe|5|src=1.2.3.4", out var cef));
        Assert.Equal("Name with | pipe", cef!.Name);
        Assert.Equal("5", cef.Severity);
        Assert.Equal("1.2.3.4", cef.Extensions["src"]);
    }

    [Fact]
    public void Maps_unifi_siem_cef_without_a_source_hint()
    {
        var e = Parse("<14>Nov 11 17:59:58 UDM-Pro CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin UNIFIhost=UDM Pro UNIFIaccessMethod=web UNIFIadmin=jdoe src=192.168.1.10 msg=jdoe accessed UniFi Network using the web. Source IP: 192.168.1.10");

        Assert.Equal("unifi.system", e.EventDataset);
        Assert.Equal("unifi", e.EventModule);
        Assert.Equal("admin_accessed_unifi_network", e.EventAction);
        Assert.Equal("jdoe", e.UserName);
        Assert.Equal("192.168.1.10", e.SourceIp);
        Assert.Equal("UDM-Pro", e.HostName);
        Assert.Equal("544", e.Fields["event.code"]);
        Assert.Equal("Admin", e.Fields["unifi.sub_category"]);
        Assert.Equal("web", e.Fields["unifi.access_method"]);
        Assert.StartsWith("jdoe accessed UniFi Network", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Maps_cef_firewall_fields()
    {
        var e = Parse("CEF:0|Ubiquiti|UniFi Network|9.3.33|400|Blocked by Firewall|4|UNIFIcategory=Security UNIFIsubCategory=Firewall src=203.0.113.9 spt=51515 dst=192.168.1.5 dpt=443 proto=TCP act=block");

        Assert.Equal("unifi.firewall", e.EventDataset); // Security/Firewall CEF joins the iptables-style lines
        Assert.Equal("block", e.EventAction);
        Assert.Equal("denied", e.Fields["event.type"]);
        Assert.Equal("203.0.113.9", e.SourceIp);
        Assert.Equal((ushort)51515, e.SourcePort);
        Assert.Equal("192.168.1.5", e.DestinationIp);
        Assert.Equal((ushort)443, e.DestinationPort);
        Assert.Equal("tcp", e.NetworkTransport);
    }

    [Fact]
    public void Maps_legacy_firewall_lines_when_source_is_tagged_unifi()
    {
        var e = Parse("<4>Nov 11 17:00:00 UDM-Pro kernel: [WAN_IN-D-3000] DESCR=\"Block inbound\" IN=eth8 OUT=br0 MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.9 DST=192.168.1.5 LEN=60 TTL=50 PROTO=TCP SPT=51515 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0", hint: "unifi");

        Assert.Equal("unifi.firewall", e.EventDataset);
        Assert.Equal("drop", e.EventAction);
        Assert.Equal("denied", e.Fields["event.type"]);
        Assert.Equal("WAN_IN-D-3000", e.Fields["rule.name"]);
        Assert.Equal("Block inbound", e.Fields["rule.description"]);
        Assert.Equal("eth8", e.Fields["observer.ingress.interface.name"]);
        Assert.Equal("203.0.113.9", e.SourceIp);
        Assert.Equal((ushort)22, e.DestinationPort);
        Assert.Equal("tcp", e.NetworkTransport);
        Assert.Equal("SYN", e.Fields["unifi.tcp_flags"]);
        Assert.Equal("warning", e.LogLevel);
        Assert.Equal("kernel", e.Fields["process.name"]);
    }

    [Fact]
    public void Untagged_iptables_lines_fall_through_to_generic_syslog()
    {
        var e = Parse("<4>Nov 11 17:00:00 somebox kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=2");
        Assert.Equal("syslog", e.EventDataset);
    }

    [Fact]
    public void Other_unifi_lines_become_unifi_system()
    {
        var e = Parse("<30>Nov 11 17:00:00 UDM-Pro hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated", hint: "unifi");
        Assert.Equal("unifi.system", e.EventDataset);
        Assert.Equal("hostapd", e.Fields["process.name"]);
    }

    [Theory]
    [InlineData("WAN_IN-D-3000", "drop")]
    [InlineData("LAN_LOCAL-A-2000", "accept")]
    [InlineData("A-WAN_IN-RET-2147483647", "accept")]
    [InlineData("WAN_LOCAL-R-1", "reject")]
    [InlineData("UFW BLOCK", null)]
    public void Firewall_rule_names_map_to_actions(string rule, string? action) =>
        Assert.Equal(action, KernelFirewall.ActionFromRule(rule));
}

public class UnifiRealWorldTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 11, 21, 34, 5, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new UnifiParser(), new SyslogParser()]);

    private LogEvent Parse(string line, string? hint = null) =>
        _registry.Parse(new RawEnvelope(Received, "syslog-udp", "10.0.1.1", line, hint), "dg");

    [Fact]
    public void Unifi_os_cef_without_pri_or_category()
    {
        var e = Parse("Nov 11 21:34:03 UDM-Office CEF:0|Ubiquiti|UniFi OS|6.0.12|1000|Admin Accessed UniFi OS|1|UNIFIhost=UDM-Office UNIFIdeviceName=UDM-Office UNIFIdeviceModel=UDMPRO UNIFIdeviceIp=203.0.113.107 UNIFIdeviceMac=02:00:5E:10:00:01 UNIFIdeviceVersion=6.0.12 UNIFIutcTime=2026-11-11T21:34:03.643Z UNIFIadmin=Jane Doe UNIFIaccessMethod=unifi.ui.com msg=Jane Doe accessed the UniFi OS using unifi.ui.com. Source IP: 198.51.100.6");

        Assert.Equal("unifi.os", e.EventDataset);
        Assert.Equal("admin_accessed_unifi_os", e.EventAction);
        Assert.Equal(new DateTimeOffset(2026, 11, 11, 21, 34, 3, 643, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("UDM-Office", e.HostName);
        Assert.Equal("UDM-Office", e.Fields["observer.name"]);
        Assert.Equal("Jane Doe", e.UserName);
        Assert.Equal("198.51.100.6", e.SourceIp);
        Assert.Equal("UDMPRO", e.Fields["unifi.device_model"]);
        Assert.Equal("unifi.ui.com", e.Fields["unifi.access_method"]);
    }

    [Fact]
    public void Access_point_tags_are_split_into_mac_model_version_and_process()
    {
        var e = Parse("<30>Nov 11 21:30:00 AP-01 942a6fc2c4dc,U7-Pro-8.8.14+20179: hostapd[1234]: ath2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated", hint: "unifi");

        Assert.Equal("unifi.ap", e.EventDataset);
        Assert.Equal("AP-01", e.HostName);
        Assert.Equal("94-2A-6F-C2-C4-DC", e.Fields["observer.mac"]);
        Assert.Equal("U7-Pro", e.Fields["observer.product"]);
        Assert.Equal("8.8.14+20179", e.Fields["observer.version"]);
        Assert.Equal("hostapd", e.Fields["process.name"]);
        Assert.Equal("1234", e.Fields["process.pid"]);
        Assert.Equal("ath2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated", e.Message);
    }

    [Fact]
    public void Generic_syslog_accepts_lines_without_pri()
    {
        var e = Parse("Nov 11 21:30:00 somehost cron[99]: job ran");
        Assert.Equal("syslog", e.EventDataset);
        Assert.Equal("somehost", e.HostName);
        Assert.Equal("cron", e.Fields["process.name"]);
        Assert.Equal("notice", e.LogLevel);
    }
}

public class SyslogTimeAndHostTests
{
    // Received 21:55:35 UTC; the gateway's clock says 15:55:34 (CST, UTC-6).
    private static readonly DateTimeOffset Received = new(2026, 11, 11, 21, 55, 35, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new UnifiParser(), new SyslogParser()]);

    [Fact]
    public void Infers_local_time_zone_and_strips_repeated_hostname()
    {
        var e = _registry.Parse(new RawEnvelope(Received, "syslog-udp", "10.0.1.1",
            "<30>Nov 11 15:55:34 UDM-Office UDM-Office ubios-udapi-server[444805]: 14[ENC] parsed QUICK_MODE request 1017869010 [ HASH ]", "unifi"), "dg");

        Assert.Equal(new DateTimeOffset(2026, 11, 11, 21, 55, 34, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("-06:00", e.Fields["event.timezone"]);
        Assert.Equal("UDM-Office", e.HostName);
        Assert.Equal("ubios-udapi-server", e.Fields["process.name"]);
        Assert.Equal("444805", e.Fields["process.pid"]);
        Assert.Equal("unifi.vpn", e.EventDataset);
        Assert.Equal("ENC", e.Fields["unifi.ipsec.subsystem"]);
        Assert.Equal("14[ENC] parsed QUICK_MODE request 1017869010 [ HASH ]", e.Message);
    }

    [Fact]
    public void Dpd_lines_are_marked_as_keepalives()
    {
        var e = _registry.Parse(new RawEnvelope(Received, "syslog-udp", "10.0.1.1",
            "<30>Nov 11 15:55:34 UDM-Office UDM-Office ubios-udapi-server[444805]: 03[ENC] generating INFORMATIONAL_V1 request 641684518 [ HASH N(DPD) ]", "unifi"), "dg");
        Assert.Equal("ipsec_keepalive", e.EventAction);
    }

    [Theory]
    [InlineData("2026-11-11T15:55:34Z", -6.0)]   // US Central
    [InlineData("2026-11-12T03:25:34Z", 5.5)]    // India
    [InlineData("2026-11-11T21:55:34Z", null)]   // sender already logs UTC
    [InlineData("2026-11-11T21:40:00Z", null)]   // 15-minute clock error: not a zone, keep as-is
    public void Resolves_wall_clock_against_receive_time(string wallClock, double? expectedOffsetHours)
    {
        var (utc, offset) = SyslogParser.ResolveLocalTime(DateTimeOffset.Parse(wallClock, System.Globalization.CultureInfo.InvariantCulture), Received);
        Assert.Equal(expectedOffsetHours, offset?.TotalHours);
        if (offset is not null)
        {
            Assert.True((utc - Received).Duration() < TimeSpan.FromMinutes(2));
        }
    }
}

public class UnifiDatasetSplitTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 12, 0, 18, 1, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new UnifiParser(), new SyslogParser()]);

    private LogEvent Parse(string line) => _registry.Parse(new RawEnvelope(Received, "syslog-udp", "10.1.1.4", line, "unifi"), "dg");

    [Fact]
    public void Dhcp_lines_get_their_own_dataset_with_client_fields()
    {
        var e = Parse("<30>Nov 12 00:17:56 UDM-Office UDM-Office dnsmasq-dhcp[1234]: DHCPACK(br0) 10.1.1.200 02:00:5e:10:00:04 LAPTOP-01");
        Assert.Equal("unifi.dhcp", e.EventDataset);
        Assert.Equal("dhcpack", e.EventAction);
        Assert.Equal("10.1.1.200", e.Fields["client.ip"]);
        Assert.Equal("02-00-5E-10-00-04", e.Fields["client.mac"]);
        Assert.Equal("LAPTOP-01", e.Fields["unifi.dhcp.hostname"]);
        Assert.Equal("br0", e.Fields["observer.ingress.interface.name"]);

        var discover = Parse("<30>Nov 12 00:17:56 UDM-Office UDM-Office dnsmasq-dhcp[1234]: DHCPDISCOVER(br0) 02:00:5e:10:00:04");
        Assert.Equal("dhcpdiscover", discover.EventAction);
        Assert.False(discover.Fields.ContainsKey("client.ip"));
    }

    [Fact]
    public void Access_point_events_go_to_unifi_ap_with_client_details()
    {
        var join = Parse("<30>Nov 12 00:17:56 AP-01 942a6fc2c4dc,U7-Pro-8.8.14+20179: wevent[999]: wevent.ubnt_custom_event(): EVENT_STA_IP wifi0ap5: 02:00:5e:10:00:04 / 10.1.1.200");
        Assert.Equal("unifi.ap", join.EventDataset);
        Assert.Equal("access-point", join.Fields["observer.type"]);
        Assert.Equal("sta_ip", join.EventAction);
        Assert.Equal("02-00-5E-10-00-04", join.Fields["client.mac"]);
        Assert.Equal("10.1.1.200", join.Fields["client.ip"]);

        var roam = Parse("<30>Nov 12 00:17:56 AP-02 942a6fc4cd60,U7-Pro-8.8.14+20179: hostapd: wifi0ap0: STA 02:00:5e:10:00:04 WPA: UBNT_ROAM received: STA roamed to peer AP 02:00:5e:10:00:05");
        Assert.Equal("unifi.ap", roam.EventDataset);
        Assert.Equal("sta_roam", roam.EventAction);
    }

    [Fact]
    public void Switches_dpi_and_the_rest()
    {
        Assert.Equal("unifi.switch", Parse("<30>Nov 12 00:00:00 SW-01 aabbccddeeff,USW-24-PoE-7.1.26+15869: switchd: port 3 link up").EventDataset);
        Assert.Equal("unifi.dpi", Parse("<30>Nov 12 00:17:57 UDM-Office UDM-Office ubnt-dpi-util: pcap dumping rate exceeded").EventDataset);
        Assert.Equal("unifi.system", Parse("<30>Nov 12 00:18:00 UDM-Office UDM-Office avahi-daemon[55]: avahi-daemon 0.8 starting up.").EventDataset);
    }
}

public class UnifiFirewallCefTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 12, 1, 26, 48, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new UnifiParser(), new SyslogParser()]);

    private LogEvent Parse(string line) => _registry.Parse(new RawEnvelope(Received, "syslog-udp", "10.10.0.1", line, "unifi"), "acme");

    [Fact]
    public void Full_firewall_block_maps_to_ecs()
    {
        var e = Parse("Nov 11 19:26:47 3939Harvard-UDM-SE CEF:0|Ubiquiti|UniFi Network|11.0.99|203|Blocked by Firewall|4|UNIFIcategory=Security UNIFIhost=3939Harvard - UDM-SE proto=TCP spt=62115 dpt=443 act=blocked app=HTTPS UNIFIrisk=low UNIFIpolicyName=DROP Invalid State UNIFIpolicyType=Firewall UNIFIdirection=outgoing deviceInboundInterface=APMCOK LAN deviceOutboundInterface=Internet 2 dst=198.51.100.137 UNIFIsrcClientAlias=iPad 66:85 UNIFIsrcClientHostname=iPad UNIFIsrcClientIp=10.10.2.117 UNIFIsrcClientMac=02:00:5e:10:00:03 UNIFIsrcClientModel=Apple iPad 10.2 (9th Gen) UNIFIsrcZone=Internal UNIFIdstRegion=US UNIFIdstZone=External UNIFIfirewallPolicy=DROP Invalid State UNIFItotalBytes=40 UNIFItotalPackets=1 UNIFIflowCount=1 UNIFIflowId=null UNIFIutcTime=2026-11-12T01:26:47.724Z msg=iPad 66:85 was blocked from accessing 198.51.100.137 by the DROP Invalid State Firewall Policy.");

        Assert.Equal("unifi.firewall", e.EventDataset);
        Assert.Equal("blocked", e.EventAction);
        Assert.Equal("denied", e.Fields["event.type"]);
        Assert.Equal("DROP Invalid State", e.Fields["rule.name"]);
        Assert.Equal("10.10.2.117", e.SourceIp);
        Assert.Equal((ushort)62115, e.SourcePort);
        Assert.Equal("198.51.100.137", e.DestinationIp);
        Assert.Equal((ushort)443, e.DestinationPort);
        Assert.Equal("tcp", e.NetworkTransport);
        Assert.Equal("https", e.NetworkProtocol);
        Assert.Equal("02-00-5E-10-00-03", e.Fields["source.mac"]);
        Assert.Equal("iPad", e.Fields["source.domain"]);
        Assert.Equal("iPad 66:85", e.Fields["source.alias"]);
        Assert.Equal("Internal", e.Fields["observer.ingress.zone"]);
        Assert.Equal("External", e.Fields["observer.egress.zone"]);
        Assert.Equal("APMCOK LAN", e.Fields["observer.ingress.interface.name"]);
        Assert.Equal("Internet 2", e.Fields["observer.egress.interface.name"]);
        Assert.Equal("outbound", e.Fields["network.direction"]);
        Assert.Equal("US", e.Fields["destination.geo.country_iso_code"]);
        Assert.Equal("40", e.Fields["network.bytes"]);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 1, 26, 47, 724, TimeSpan.Zero), e.Timestamp);
        Assert.False(e.Fields.ContainsKey("unifi.src_client_ip")); // mapped, not duplicated
    }

    [Fact]
    public void Minimal_firewall_block_without_act_or_ports()
    {
        var e = Parse("Nov 11 19:19:19 3939Harvard-UDM-SE CEF:0|Ubiquiti|UniFi Network|11.0.99|203|Blocked by Firewall|4|UNIFIcategory=Security UNIFIhost=3939Harvard - UDM-SE dst=8.8.4.4 UNIFIsrcClientAlias=Apple iPad Pro 9.7 c0:8f UNIFIsrcClientIp=10.10.2.194 UNIFIsrcClientMac=02:00:5e:10:00:02 UNIFIsrcClientModel=Apple iPad Pro 9.7 UNIFIfirewallPolicy=DROP Invalid State UNIFIutcTime=2026-11-12T01:19:19.066Z msg=Apple iPad Pro 9.7 c0:8f was blocked from accessing 8.8.4.4 by the DROP Invalid State Firewall Policy.");

        Assert.Equal("unifi.firewall", e.EventDataset);
        Assert.Equal("blocked", e.EventAction); // from the event name, not "blocked_by_firewall"
        Assert.Equal("denied", e.Fields["event.type"]);
        Assert.Equal("10.10.2.194", e.SourceIp);
        Assert.Equal("8.8.4.4", e.DestinationIp);
        Assert.Equal("DROP Invalid State", e.Fields["rule.name"]);
    }
}
