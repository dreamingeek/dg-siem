using System.Globalization;
using System.Net;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers.Vendors;

/// <summary>
/// Windows events from the agent's event log input (input <c>wineventlog:&lt;channel&gt;</c>, the event's XML with
/// <c>RenderingInfo</c>). Fields follow Winlogbeat: <c>winlog.event_id</c>, <c>winlog.channel</c>,
/// <c>winlog.event_data.*</c>, plus ECS where it fits (<c>user.name</c>, <c>source.ip</c>, <c>process.*</c>).
/// Datasets: <c>windows.security</c>, <c>windows.system</c>, <c>windows.application</c>, <c>windows.sysmon</c>,
/// <c>windows.powershell</c>, <c>windows.defender</c>, or <c>windows.&lt;channel&gt;</c>.
/// </summary>
public sealed class WindowsEventParser : IEventParser
{
    public const string Module = "windows";
    public const string InputPrefix = "wineventlog:";

    public string Dataset => "windows.security";
    public int Priority => 10;

    public bool CanParse(RawEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return envelope.Input.StartsWith(InputPrefix, StringComparison.Ordinal) && envelope.Message.StartsWith("<Event", StringComparison.Ordinal);
    }

    public bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        logEvent = null;
        XElement root;
        try
        {
            root = XElement.Parse(envelope.Message, LoadOptions.None);
        }
        catch (XmlException)
        {
            return false;
        }

        var system = Child(root, "System");
        if (system is null)
        {
            return false;
        }
        var provider = Attr(Child(system, "Provider"), "Name") ?? string.Empty;
        var id = int.TryParse(Text(Child(system, "EventID")), NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId) ? eventId : 0;
        var channel = Text(Child(system, "Channel")) ?? envelope.Input[InputPrefix.Length..];
        var rendering = Child(root, "RenderingInfo");
        var data = EventData(root);

        var e = new LogEvent
        {
            TenantId = tenantId,
            Timestamp = DateTimeOffset.TryParse(Attr(Child(system, "TimeCreated"), "SystemTime"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var created) ? created : envelope.ReceivedAt,
            HostName = Text(Child(system, "Computer")) ?? string.Empty,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventDataset = envelope.DatasetHint ?? DatasetFor(channel),
            EventModule = Module,
            LogLevel = Level(Text(Child(system, "Level")), Text(Child(rendering, "Level"))),
            Message = (Text(Child(rendering, "Message")) ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal).Trim(),
            Raw = envelope.Message,
        };
        var f = e.Fields;
        f["event.code"] = id.ToString(CultureInfo.InvariantCulture);
        f["event.provider"] = provider;
        f["winlog.event_id"] = f["event.code"];
        f["winlog.channel"] = channel;
        f["winlog.provider_name"] = provider;
        f["winlog.computer_name"] = e.HostName;
        Put(f, "winlog.record_id", Text(Child(system, "EventRecordID")));
        Put(f, "winlog.process.pid", Attr(Child(system, "Execution"), "ProcessID"));
        Put(f, "winlog.process.thread.id", Attr(Child(system, "Execution"), "ThreadID"));
        Put(f, "winlog.user.identifier", Attr(Child(system, "Security"), "UserID"));
        Put(f, "winlog.task", Text(Child(rendering, "Task")));
        Put(f, "winlog.opcode", Text(Child(rendering, "Opcode")));
        var keywords = Child(rendering, "Keywords")?.Elements().Select(k => k.Value).Where(k => k.Length > 0).ToList() ?? [];
        if (keywords.Count > 0)
        {
            f["winlog.keywords"] = string.Join(", ", keywords);
        }
        foreach (var (key, value) in data)
        {
            if (value.Length > 0 && value != "-")
            {
                f[$"winlog.event_data.{key}"] = value;
            }
        }

        // Audit Success / Audit Failure decide the outcome of security events.
        if (keywords.Contains("Audit Failure") || (Text(Child(system, "Keywords")) ?? "").StartsWith("0x8010", StringComparison.OrdinalIgnoreCase))
        {
            e.EventOutcome = "failure";
        }
        else if (keywords.Contains("Audit Success") || (Text(Child(system, "Keywords")) ?? "").StartsWith("0x8020", StringComparison.OrdinalIgnoreCase))
        {
            e.EventOutcome = "success";
        }

        var kind = Kind(channel, provider);
        switch (kind)
        {
            case Source.Security:
                Security(id, data, e);
                break;
            case Source.Sysmon:
                Sysmon(id, data, e);
                break;
            case Source.PowerShell:
                PowerShell(id, data, e);
                break;
            case Source.Defender:
                Defender(id, data, e);
                break;
            default:
                SystemOrApplication(provider, id, data, e);
                break;
        }
        if (e.EventAction.Length == 0)
        {
            e.EventAction = Kebab(Text(Child(rendering, "Task")) is { Length: > 0 } task && task != "None" ? task : $"event-{id}");
        }
        if (e.EventOutcome.Length == 0 && e.LogLevel is "error" or "critical")
        {
            e.EventOutcome = "failure";
        }
        if (e.Message.Length == 0)
        {
            e.Message = $"{provider} event {id}";
        }
        logEvent = e;
        return true;
    }

    // ---- Security log ------------------------------------------------------------------------

    /// <summary>Who the event is about: the account signing in, created, locked out...</summary>
    private enum Who { Target, Subject }

    private static readonly Dictionary<int, (string Action, Who User, string? Category)> SecurityEvents = new()
    {
        [4624] = ("logged-in", Who.Target, "authentication"),
        [4625] = ("logon-failed", Who.Target, "authentication"),
        [4634] = ("logged-out", Who.Target, "authentication"),
        [4647] = ("logged-out", Who.Target, "authentication"),
        [4648] = ("logged-in-explicit", Who.Subject, "authentication"),
        [4672] = ("logged-in-special", Who.Subject, "authentication"),
        [4768] = ("kerberos-authentication-ticket-requested", Who.Target, "authentication"),
        [4769] = ("kerberos-service-ticket-requested", Who.Target, "authentication"),
        [4770] = ("kerberos-service-ticket-renewed", Who.Target, "authentication"),
        [4771] = ("kerberos-preauth-failed", Who.Target, "authentication"),
        [4776] = ("credential-validated", Who.Target, "authentication"),
        [4778] = ("session-reconnected", Who.Target, "authentication"),
        [4779] = ("session-disconnected", Who.Target, "authentication"),
        [4800] = ("workstation-locked", Who.Target, "authentication"),
        [4801] = ("workstation-unlocked", Who.Target, "authentication"),
        [4720] = ("added-user-account", Who.Subject, "iam"),
        [4722] = ("enabled-user-account", Who.Subject, "iam"),
        [4723] = ("changed-password", Who.Subject, "iam"),
        [4724] = ("reset-password", Who.Subject, "iam"),
        [4725] = ("disabled-user-account", Who.Subject, "iam"),
        [4726] = ("deleted-user-account", Who.Subject, "iam"),
        [4738] = ("modified-user-account", Who.Subject, "iam"),
        [4740] = ("locked-out-user-account", Who.Target, "iam"),
        [4767] = ("unlocked-user-account", Who.Subject, "iam"),
        [4781] = ("renamed-user-account", Who.Subject, "iam"),
        [4727] = ("added-group", Who.Subject, "iam"),
        [4731] = ("added-group", Who.Subject, "iam"),
        [4754] = ("added-group", Who.Subject, "iam"),
        [4730] = ("deleted-group", Who.Subject, "iam"),
        [4734] = ("deleted-group", Who.Subject, "iam"),
        [4758] = ("deleted-group", Who.Subject, "iam"),
        [4728] = ("added-member-to-group", Who.Subject, "iam"),
        [4732] = ("added-member-to-group", Who.Subject, "iam"),
        [4756] = ("added-member-to-group", Who.Subject, "iam"),
        [4729] = ("removed-member-from-group", Who.Subject, "iam"),
        [4733] = ("removed-member-from-group", Who.Subject, "iam"),
        [4757] = ("removed-member-from-group", Who.Subject, "iam"),
        [4688] = ("created-process", Who.Subject, "process"),
        [4689] = ("exited-process", Who.Subject, "process"),
        [4697] = ("service-installed", Who.Subject, "configuration"),
        [4698] = ("created-scheduled-task", Who.Subject, "configuration"),
        [4699] = ("deleted-scheduled-task", Who.Subject, "configuration"),
        [4700] = ("enabled-scheduled-task", Who.Subject, "configuration"),
        [4701] = ("disabled-scheduled-task", Who.Subject, "configuration"),
        [4702] = ("updated-scheduled-task", Who.Subject, "configuration"),
        [4719] = ("changed-audit-config", Who.Subject, "configuration"),
        [4616] = ("changed-system-time", Who.Subject, "configuration"),
        [1102] = ("audit-log-cleared", Who.Subject, "configuration"),
        [5140] = ("network-share-object-accessed", Who.Subject, "file"),
        [5145] = ("network-share-object-access-checked", Who.Subject, "file"),
    };

    /// <summary>Logon types (4624/4625 LogonType).</summary>
    private static readonly Dictionary<string, string> LogonTypes = new()
    {
        ["0"] = "System", ["2"] = "Interactive", ["3"] = "Network", ["4"] = "Batch", ["5"] = "Service", ["7"] = "Unlock",
        ["8"] = "NetworkCleartext", ["9"] = "NewCredentials", ["10"] = "RemoteInteractive", ["11"] = "CachedInteractive",
        ["12"] = "CachedRemoteInteractive", ["13"] = "CachedUnlock",
    };

    /// <summary>NTSTATUS codes in 4625/4776/4771 Status/SubStatus/FailureCode.</summary>
    private static readonly Dictionary<string, string> FailureReasons = new(StringComparer.OrdinalIgnoreCase)
    {
        ["0xC0000064"] = "No such user", ["0xC000006A"] = "Wrong password", ["0xC000006D"] = "Bad user name or password",
        ["0xC000006E"] = "Account restriction", ["0xC000006F"] = "Outside allowed hours", ["0xC0000070"] = "Workstation not allowed",
        ["0xC0000071"] = "Password expired", ["0xC0000072"] = "Account disabled", ["0xC0000133"] = "Clock skew",
        ["0xC000015B"] = "Logon type not granted", ["0xC0000193"] = "Account expired", ["0xC0000224"] = "Password must change",
        ["0xC0000234"] = "Account locked out", ["0xC00002EE"] = "Failure during logon", ["0xC0000413"] = "Authentication firewall",
        ["0x6"] = "No such user", ["0x12"] = "Account disabled, expired or locked out", ["0x17"] = "Password expired",
        ["0x18"] = "Wrong password", ["0x25"] = "Clock skew",
    };

    private static void Security(int id, Dictionary<string, string> d, LogEvent e)
    {
        var f = e.Fields;
        if (SecurityEvents.TryGetValue(id, out var known))
        {
            e.EventAction = known.Action;
            if (known.Category is { } category)
            {
                f["event.category"] = category;
            }
            var (name, domain, sid) = known.User == Who.Target
                ? (Val(d, "TargetUserName"), Val(d, "TargetDomainName"), Val(d, "TargetUserSid") ?? Val(d, "TargetSid"))
                : (Val(d, "SubjectUserName"), Val(d, "SubjectDomainName"), Val(d, "SubjectUserSid"));
            User(e, name, domain, sid);
            // The other party: who was created / added / changed, or who the subject acted as.
            if (known.User == Who.Subject && Val(d, "TargetUserName") is { } target && id is not (4688 or 4689))
            {
                f["user.target.name"] = target;
                Put(f, "user.target.domain", Val(d, "TargetDomainName"));
            }
        }

        // Where it came from.
        SetIp(e, Val(d, "IpAddress") ?? Val(d, "ClientAddress"), isSource: true);
        if (ushort.TryParse(Val(d, "IpPort") ?? Val(d, "ClientPort"), NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port > 0)
        {
            e.SourcePort = port;
        }
        Put(f, "source.domain", Val(d, "WorkstationName") ?? Val(d, "Workstation"));

        if (Val(d, "LogonType") is { } logonType)
        {
            f["winlog.logon.type"] = LogonTypes.GetValueOrDefault(logonType, logonType);
        }
        Put(f, "winlog.logon.id", Val(d, "TargetLogonId") ?? Val(d, "SubjectLogonId"));
        if ((Val(d, "SubStatus") is { } sub && sub != "0x0" ? sub : Val(d, "Status") ?? Val(d, "FailureCode")) is { } status && status != "0x0")
        {
            f["winlog.logon.failure.status"] = status;
            Put(f, "winlog.logon.failure.reason", FailureReasons.GetValueOrDefault(status));
            if (id is 4776 or 4771)
            {
                e.EventOutcome = "failure";
            }
        }
        Put(f, "winlog.logon.failure.reason", Val(d, "FailureReason") is { } fr && fr.StartsWith("%%", StringComparison.Ordinal) ? null : Val(d, "FailureReason"));

        // Group membership: the group and the member.
        if (id is 4727 or 4728 or 4729 or 4730 or 4731 or 4732 or 4733 or 4734 or 4754 or 4756 or 4757 or 4758)
        {
            Put(f, "group.name", Val(d, "TargetUserName"));
            Put(f, "group.domain", Val(d, "TargetDomainName"));
            f.Remove("user.target.name");
            f.Remove("user.target.domain");
            if (Val(d, "MemberName") is { } member)
            {
                f["user.target.name"] = CommonName(member);
            }
            Put(f, "user.target.id", Val(d, "MemberSid"));
        }

        // Processes: 4688 new process, 4689 exit, and the process behind a logon.
        if (id == 4688)
        {
            Process(f, "process", Val(d, "NewProcessName"), Hex(Val(d, "NewProcessId")), Val(d, "CommandLine"));
            Process(f, "process.parent", Val(d, "ParentProcessName"), Hex(Val(d, "ProcessId")), null);
            if (Val(d, "TargetUserName") is { } runAs && Val(d, "TargetUserSid") is not "S-1-0-0")
            {
                f["user.effective.name"] = runAs;
            }
        }
        else if (Val(d, "ProcessName") is { } processName)
        {
            Process(f, "process", processName, Hex(Val(d, "ProcessId")), null);
        }

        Put(f, "service.name", Val(d, "ServiceName"));
        Put(f, "winlog.event_data.task_name", Val(d, "TaskName"));
        if (id == 5140 || id == 5145)
        {
            Put(f, "file.path", Val(d, "ShareName") is { } share ? share + (Val(d, "RelativeTargetName") is { } rel ? "\\" + rel : "") : null);
        }
        if (id == 1102)
        {
            e.LogLevel = "warning";
        }
    }

    // ---- System / Application ----------------------------------------------------------------

    private static void SystemOrApplication(string provider, int id, Dictionary<string, string> d, LogEvent e)
    {
        var f = e.Fields;
        switch (provider, id)
        {
            case ("Service Control Manager", 7045):
                e.EventAction = "service-installed";
                Put(f, "service.name", Val(d, "ServiceName"));
                Put(f, "process.executable", Val(d, "ImagePath"));
                Put(f, "service.type", Val(d, "StartType"));
                User(e, Val(d, "AccountName"), null, null);
                break;
            case ("Service Control Manager", 7036):
                e.EventAction = "service-state-changed";
                Put(f, "service.name", Val(d, "param1"));
                Put(f, "service.state", Val(d, "param2"));
                break;
            case ("Service Control Manager", 7040):
                e.EventAction = "service-start-type-changed";
                Put(f, "service.name", Val(d, "param1"));
                break;
            case ("Service Control Manager", 7031 or 7034):
                e.EventAction = "service-crashed";
                e.EventOutcome = "failure";
                Put(f, "service.name", Val(d, "param1"));
                break;
            case ("EventLog", 6005):
                e.EventAction = "eventlog-started";
                break;
            case ("EventLog", 6006):
                e.EventAction = "eventlog-stopped";
                break;
            case ("EventLog", 6008):
                e.EventAction = "unexpected-shutdown";
                e.EventOutcome = "failure";
                break;
            case ("Microsoft-Windows-Eventlog", 104):
                e.EventAction = "log-cleared";
                e.LogLevel = "warning";
                User(e, Val(d, "SubjectUserName"), Val(d, "SubjectDomainName"), null);
                Put(f, "winlog.event_data.cleared_channel", Val(d, "Channel"));
                break;
            case ("User32", 1074):
                e.EventAction = "shutdown-initiated";
                Put(f, "process.executable", Val(d, "param1"));
                Put(f, "winlog.event_data.reason", Val(d, "param3"));
                if (Val(d, "param7") is { } who && who.Contains('\\', StringComparison.Ordinal))
                {
                    User(e, who[(who.IndexOf('\\', StringComparison.Ordinal) + 1)..], who[..who.IndexOf('\\', StringComparison.Ordinal)], null);
                }
                break;
            case ("Microsoft-Windows-Kernel-Power", 41):
                e.EventAction = "unexpected-reboot";
                e.EventOutcome = "failure";
                break;
            case ("Application Error", 1000):
                e.EventAction = "application-crashed";
                e.EventOutcome = "failure";
                Put(f, "process.name", Val(d, "AppName") ?? Val(d, "param1"));
                Put(f, "process.executable", Val(d, "AppPath") ?? Val(d, "param11"));
                break;
            case ("Application Hang", 1002):
                e.EventAction = "application-hung";
                e.EventOutcome = "failure";
                Put(f, "process.name", Val(d, "param1"));
                break;
            case ("MsiInstaller", 11707 or 1033):
                e.EventAction = "product-installed";
                break;
            case ("MsiInstaller", 11724 or 1034):
                e.EventAction = "product-removed";
                break;
        }
    }

    // ---- Sysmon ------------------------------------------------------------------------------

    private static readonly Dictionary<int, string> SysmonActions = new()
    {
        [1] = "process-created", [2] = "file-creation-time-changed", [3] = "network-connection", [4] = "sysmon-state-changed",
        [5] = "process-terminated", [6] = "driver-loaded", [7] = "image-loaded", [8] = "remote-thread-created",
        [9] = "raw-disk-read", [10] = "process-accessed", [11] = "file-created", [12] = "registry-key-created-or-deleted",
        [13] = "registry-value-set", [14] = "registry-renamed", [15] = "file-stream-created", [16] = "sysmon-config-changed",
        [17] = "pipe-created", [18] = "pipe-connected", [19] = "wmi-filter", [20] = "wmi-consumer", [21] = "wmi-binding",
        [22] = "dns-query", [23] = "file-deleted", [24] = "clipboard-changed", [25] = "process-tampering",
        [26] = "file-delete-logged", [27] = "file-block-executable", [28] = "file-block-shredding", [29] = "file-executable-detected",
        [255] = "sysmon-error",
    };

    private static void Sysmon(int id, Dictionary<string, string> d, LogEvent e)
    {
        var f = e.Fields;
        e.EventModule = "sysmon";
        e.EventAction = SysmonActions.GetValueOrDefault(id, $"event-{id}");
        f["event.category"] = id switch
        {
            1 or 5 or 8 or 10 or 25 => "process",
            3 or 22 => "network",
            12 or 13 or 14 => "registry",
            6 or 7 => "driver",
            _ => "file",
        };
        Put(f, "rule.name", Val(d, "RuleName"));
        Process(f, "process", Val(d, "Image") ?? Val(d, "SourceImage"), Val(d, "ProcessId") ?? Val(d, "SourceProcessId"), Val(d, "CommandLine"));
        Process(f, "process.parent", Val(d, "ParentImage"), Val(d, "ParentProcessId"), Val(d, "ParentCommandLine"));
        Put(f, "process.working_directory", Val(d, "CurrentDirectory"));
        Put(f, "process.pe.original_file_name", Val(d, "OriginalFileName"));
        if (Val(d, "User") is { } user)
        {
            var slash = user.IndexOf('\\', StringComparison.Ordinal);
            User(e, slash >= 0 ? user[(slash + 1)..] : user, slash >= 0 ? user[..slash] : null, null);
        }
        // SHA256=…,MD5=…,IMPHASH=… → process.hash.* for new processes, file.hash.* otherwise.
        if ((Val(d, "Hashes") ?? Val(d, "Hash")) is { } hashes)
        {
            var prefix = id == 1 ? "process.hash" : "file.hash";
            foreach (var part in hashes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var eq = part.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0)
                {
                    f[$"{prefix}.{part[..eq].ToLowerInvariant()}"] = part[(eq + 1)..].ToLowerInvariant();
                }
            }
        }
        switch (id)
        {
            case 3:
                SetIp(e, Val(d, "SourceIp"), isSource: true);
                SetIp(e, Val(d, "DestinationIp"), isSource: false);
                e.SourcePort = Port(Val(d, "SourcePort"));
                e.DestinationPort = Port(Val(d, "DestinationPort"));
                e.NetworkTransport = (Val(d, "Protocol") ?? string.Empty).ToLowerInvariant();
                Put(f, "source.domain", Val(d, "SourceHostname"));
                Put(f, "destination.domain", Val(d, "DestinationHostname"));
                f["network.direction"] = Val(d, "Initiated") == "true" ? "outbound" : "inbound";
                break;
            case 22:
                e.NetworkProtocol = "dns";
                Put(f, "dns.question.name", Val(d, "QueryName"));
                Put(f, "dns.answers", Val(d, "QueryResults"));
                Put(f, "dns.response_code", Val(d, "QueryStatus"));
                break;
            case 6 or 7:
                Put(f, "file.path", Val(d, "ImageLoaded"));
                Put(f, "file.code_signature.subject_name", Val(d, "Signature"));
                Put(f, "file.code_signature.status", Val(d, "SignatureStatus"));
                break;
            case 8 or 10:
                Process(f, "process.target", Val(d, "TargetImage"), Val(d, "TargetProcessId"), null);
                Put(f, "winlog.event_data.GrantedAccess", Val(d, "GrantedAccess"));
                break;
            case 12 or 13 or 14:
                Put(f, "registry.path", Val(d, "TargetObject"));
                Put(f, "registry.data.strings", Val(d, "Details"));
                break;
            case 17 or 18:
                Put(f, "file.name", Val(d, "PipeName"));
                break;
            default:
                Put(f, "file.path", Val(d, "TargetFilename"));
                break;
        }
    }

    // ---- PowerShell --------------------------------------------------------------------------

    private static void PowerShell(int id, Dictionary<string, string> d, LogEvent e)
    {
        var f = e.Fields;
        e.EventModule = "powershell";
        switch (id)
        {
            case 4104:
                e.EventAction = "script-block-logged";
                f["event.category"] = "process";
                Put(f, "powershell.file.script_block_text", Val(d, "ScriptBlockText"));
                Put(f, "powershell.file.script_block_id", Val(d, "ScriptBlockId"));
                Put(f, "file.path", Val(d, "Path"));
                if (Val(d, "MessageTotal") is { } total && total != "1")
                {
                    f["powershell.sequence"] = Val(d, "MessageNumber") ?? "1";
                    f["powershell.total"] = total;
                }
                break;
            case 4103:
                e.EventAction = "module-logged";
                break;
            case 400:
                e.EventAction = "engine-started";
                break;
            case 403:
                e.EventAction = "engine-stopped";
                break;
            case 800:
                e.EventAction = "pipeline-executed";
                break;
        }
        Put(f, "user.id", f.GetValueOrDefault("winlog.user.identifier"));
    }

    // ---- Defender ----------------------------------------------------------------------------

    private static void Defender(int id, Dictionary<string, string> d, LogEvent e)
    {
        var f = e.Fields;
        e.EventModule = "defender";
        (e.EventAction, var outcome, var alert) = id switch
        {
            1006 or 1116 => ("malware-detected", "", true),
            1007 or 1117 => ("malware-action-taken", "success", true),
            1008 or 1118 or 1119 => ("malware-action-failed", "failure", true),
            1015 => ("suspicious-behavior-detected", "", true),
            1000 => ("scan-started", "", false),
            1001 => ("scan-finished", "success", false),
            1002 => ("scan-stopped", "", false),
            1005 => ("scan-failed", "failure", false),
            2000 => ("signatures-updated", "success", false),
            2001 => ("signature-update-failed", "failure", false),
            3002 => ("real-time-protection-failed", "failure", false),
            5000 => ("real-time-protection-enabled", "", false),
            5001 => ("real-time-protection-disabled", "", false),
            5004 => ("real-time-protection-config-changed", "", false),
            5007 => ("config-changed", "", false),
            5008 => ("engine-failed", "failure", false),
            5010 => ("spyware-scanning-disabled", "", false),
            5012 => ("virus-scanning-disabled", "", false),
            5013 => ("tamper-protection-blocked-change", "", true),
            _ => (string.Empty, "", false),
        };
        if (outcome.Length > 0)
        {
            e.EventOutcome = outcome;
        }
        if (alert)
        {
            f["event.kind"] = "alert";
            f["event.category"] = "malware";
        }
        if (id is 5001 or 5010 or 5012)
        {
            e.LogLevel = "warning";
        }
        Put(f, "threat.name", Val(d, "Threat_Name"));
        Put(f, "threat.id", Val(d, "Threat_ID"));
        Put(f, "defender.severity", Val(d, "Severity_Name"));
        Put(f, "defender.category", Val(d, "Category_Name"));
        Put(f, "defender.action", Val(d, "Action_Name"));
        Put(f, "defender.error", Val(d, "Error_Description") is { } err && err != "The operation completed successfully. " ? err.Trim() : null);
        // Path: "file:_C:\Users\x\Downloads\bad.exe; containerfile:_…"
        if (Val(d, "Path") is { } path)
        {
            var first = path.Split(';')[0].Trim();
            var underscore = first.IndexOf(":_", StringComparison.Ordinal);
            f["file.path"] = underscore >= 0 ? first[(underscore + 2)..] : first;
        }
        Put(f, "process.executable", Val(d, "Process_Name") is { } p && p != "Unknown" ? p : null);
        if ((Val(d, "Detection_User") ?? Val(d, "Remediation_User")) is { Length: > 0 } user)
        {
            var slash = user.IndexOf('\\', StringComparison.Ordinal);
            User(e, slash >= 0 ? user[(slash + 1)..] : user, slash >= 0 ? user[..slash] : null, null);
        }
    }

    // ---- Shared ------------------------------------------------------------------------------

    private enum Source { Security, Sysmon, PowerShell, Defender, Other }

    private static Source Kind(string channel, string provider) => channel switch
    {
        "Security" => Source.Security,
        "Microsoft-Windows-Sysmon/Operational" => Source.Sysmon,
        "Microsoft-Windows-PowerShell/Operational" or "Windows PowerShell" or "PowerShellCore/Operational" => Source.PowerShell,
        "Microsoft-Windows-Windows Defender/Operational" => Source.Defender,
        _ when provider == "Microsoft-Windows-Sysmon" => Source.Sysmon,
        _ => Source.Other,
    };

    /// <summary><c>Security</c> → <c>windows.security</c>, <c>Microsoft-Windows-Sysmon/Operational</c> → <c>windows.sysmon</c>.</summary>
    public static string DatasetFor(string channel) => channel switch
    {
        "Security" => "windows.security",
        "System" => "windows.system",
        "Application" => "windows.application",
        "Microsoft-Windows-Sysmon/Operational" => "windows.sysmon",
        "Microsoft-Windows-PowerShell/Operational" or "Windows PowerShell" or "PowerShellCore/Operational" => "windows.powershell",
        "Microsoft-Windows-Windows Defender/Operational" => "windows.defender",
        _ => "windows." + Slug(channel.StartsWith("Microsoft-Windows-", StringComparison.Ordinal) ? channel[18..] : channel),
    };

    /// <summary><c>TaskScheduler/Operational</c> → <c>taskscheduler</c>, <c>Directory Service</c> → <c>directory.service</c>.</summary>
    private static string Slug(string value)
    {
        var parts = new string(value.ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '.').ToArray())
            .Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => p != "operational");
        var slug = string.Join('.', parts);
        return slug.Length == 0 ? "other" : slug.Length > 48 ? slug[..48].TrimEnd('.') : slug;
    }

    /// <summary>
    /// EventData <c>&lt;Data Name="x"&gt;</c> (names with spaces become underscores; unnamed ones <c>param1</c>…),
    /// or the elements under UserData.
    /// </summary>
    private static Dictionary<string, string> EventData(XElement root)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        if (Child(root, "EventData") is { } eventData)
        {
            var n = 0;
            foreach (var item in eventData.Elements())
            {
                if (item.Name.LocalName == "Data")
                {
                    n++;
                    var name = Attr(item, "Name") is { Length: > 0 } named ? Key(named) : $"param{n}";
                    values.TryAdd(name, item.Value.Trim());
                }
                else if (item.Name.LocalName == "Binary" && item.Value.Length is > 0 and <= 512)
                {
                    values.TryAdd("Binary", item.Value);
                }
            }
        }
        if (Child(root, "UserData")?.Elements().FirstOrDefault() is { } userData)
        {
            foreach (var item in userData.Descendants().Where(x => !x.HasElements))
            {
                values.TryAdd(Key(item.Name.LocalName), item.Value.Trim());
            }
        }
        return values;
    }

    private static string Key(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.Trim())
        {
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' ? c : '_');
        }
        return sb.ToString();
    }

    private static string Level(string? code, string? text) => code switch
    {
        "1" => "critical",
        "2" => "error",
        "3" => "warning",
        "5" => "debug",
        _ => text switch
        {
            "Critical" => "critical",
            "Error" => "error",
            "Warning" => "warning",
            _ => "informational",
        },
    };

    private static void User(LogEvent e, string? name, string? domain, string? sid)
    {
        if (name is null || name == "-")
        {
            return;
        }
        e.UserName = name;
        Put(e.Fields, "user.domain", domain is "-" ? null : domain);
        Put(e.Fields, "user.id", sid is "S-1-0-0" ? null : sid);
    }

    private static void Process(Dictionary<string, string> f, string prefix, string? executable, string? pid, string? commandLine)
    {
        if (executable is not null)
        {
            f[$"{prefix}.executable"] = executable;
            var slash = executable.LastIndexOfAny(['\\', '/']);
            f[$"{prefix}.name"] = slash >= 0 ? executable[(slash + 1)..] : executable;
        }
        Put(f, $"{prefix}.pid", pid);
        Put(f, $"{prefix}.command_line", commandLine);
    }

    /// <summary><c>0x1a2c</c> → <c>6700</c> (the Security log writes process ids in hex).</summary>
    private static string? Hex(string? value) =>
        value is not null && value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && long.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var n)
            ? n.ToString(CultureInfo.InvariantCulture) : value;

    private static ushort Port(string? value) =>
        ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : (ushort)0;

    private static void SetIp(LogEvent e, string? value, bool isSource)
    {
        if (value is null || !IPAddress.TryParse(value.Trim('[', ']'), out var ip))
        {
            return;
        }
        var text = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
        if (isSource)
        {
            e.SourceIp = text;
        }
        else
        {
            e.DestinationIp = text;
        }
    }

    /// <summary><c>CN=Jane Doe,OU=Users,DC=corp,DC=example</c> → <c>Jane Doe</c>.</summary>
    private static string CommonName(string dn)
    {
        if (!dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
        {
            return dn;
        }
        // The first comma that isn't escaped ("Doe\, Jr") ends the name.
        for (var i = 3; i < dn.Length; i++)
        {
            if (dn[i] == '\\')
            {
                i++;
            }
            else if (dn[i] == ',')
            {
                return dn[3..i].Replace("\\,", ",", StringComparison.Ordinal);
            }
        }
        return dn[3..].Replace("\\,", ",", StringComparison.Ordinal);
    }

    private static string Kebab(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                sb.Append(c);
            }
            else if (sb.Length > 0 && sb[^1] != '-')
            {
                sb.Append('-');
            }
        }
        return sb.ToString().Trim('-');
    }

    private static string? Val(Dictionary<string, string> d, string key) =>
        d.TryGetValue(key, out var v) && v.Length > 0 && v != "-" ? v : null;

    private static void Put(Dictionary<string, string> f, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value) && value != "-")
        {
            f[key] = value;
        }
    }

    private static XElement? Child(XElement? parent, string name) => parent?.Elements().FirstOrDefault(x => x.Name.LocalName == name);

    private static string? Text(XElement? element) => element is null || element.Value.Length == 0 ? null : element.Value;

    private static string? Attr(XElement? element, string name) => element?.Attribute(name)?.Value;
}
