using System.Text.Json;
using System.Text.Json.Serialization;

namespace DreaminGeek.Siem.Core.Agents;

/// <summary>Agent → server, first contact. Sent over TLS to the agent port, no client cert yet.</summary>
/// <param name="Token">Enrollment token from <c>dg-siem-server token create</c>.</param>
/// <param name="Name">Agent name, e.g. <c>acme-log-col</c>. Re-enrolling an existing name needs a token made for that name; it replaces the old certificate.</param>
/// <param name="CsrPem">PKCS#10 request for the agent's key. The private key never leaves the agent.</param>
/// <param name="Version">Agent version.</param>
/// <param name="Platform"><c>linux</c> or <c>windows</c>: picks a new agent's default inputs. Older agents don't send it.</param>
public sealed record EnrollRequest(string Token, string Name, string CsrPem, string Version, string? Platform = null);

/// <summary>Server → agent. The certificate is used for every later call (mTLS).</summary>
public sealed record EnrollResponse(Guid AgentId, string TenantSlug, string CertificatePem, string CaCertificatePem, AgentConfig Config);

/// <summary>Server → agent: a newer agent version for its platform (<c>GET /api/v1/agent/update</c>).</summary>
/// <param name="Sha256">Lower-case hex SHA-256 of the binary; the agent refuses anything else.</param>
public sealed record AgentUpdateInfo(string Version, string Platform, string Sha256, long Size);

/// <summary>Agent → server, over mTLS, to replace a certificate before it expires.</summary>
public sealed record RenewRequest(string CsrPem);

public sealed record RenewResponse(string CertificatePem);

/// <summary>Body of <c>POST /api/v1/agent/ingest</c> (gzip). Identity and tenant come from the client certificate.</summary>
public sealed record AgentIngestBatch(IReadOnlyList<RawEnvelope> Events);

/// <summary>
/// Inputs and source hints an agent runs. Stored per agent on the server and pulled by the agent,
/// so every site collector is configured centrally from the same template.
/// </summary>
public sealed class AgentConfig
{
    public List<InputConfig> Inputs { get; set; } =
    [
        new() { Type = InputType.SyslogUdp, Port = 514 },
        new() { Type = InputType.SyslogTcp, Port = 514 },
    ];

    /// <summary>Tag lines by sender, e.g. the UDM at 192.168.1.1 → <c>unifi</c>. First match wins.</summary>
    public List<SourceHint> SourceHints { get; set; } = [];

    /// <summary>How often the agent re-pulls this config.</summary>
    public int ConfigPollSeconds { get; set; } = 60;

    /// <summary>A new agent's config for its platform: syslog listeners on Linux, the event logs on Windows.</summary>
    public static AgentConfig DefaultFor(string? platform) =>
        string.Equals(platform, "windows", StringComparison.OrdinalIgnoreCase)
            ? new AgentConfig { Inputs = [new InputConfig { Type = InputType.WindowsEventLog, Channels = EventLogChannel.Defaults() }] }
            : new AgentConfig();
}

/// <summary>One Windows event log to read, optionally filtered with an event-log XPath query.</summary>
public sealed class EventLogChannel
{
    /// <summary>e.g. <c>Security</c>, <c>Microsoft-Windows-Sysmon/Operational</c>.</summary>
    public required string Name { get; set; }

    /// <summary>
    /// Event-log XPath, e.g. <c>*[System[(EventID=4104)]]</c>. Null reads everything. Applied by Windows, so
    /// filtered events never leave the machine.
    /// </summary>
    public string? Query { get; set; }

    /// <summary>
    /// Sign-ins and account changes, services and crashes, Sysmon and PowerShell script blocks (when enabled),
    /// and Defender detections. High-volume, low-value IDs are filtered out at the source.
    /// </summary>
    public static List<EventLogChannel> Defaults() =>
    [
        // 5152/5156-5158: Filtering Platform connections (huge when enabled); 4658/4690: handle closes/duplicates.
        new() { Name = "Security", Query = "*[System[(EventID!=5152 and EventID!=5156 and EventID!=5157 and EventID!=5158 and EventID!=4658 and EventID!=4690)]]" },
        new() { Name = "System" },
        new() { Name = "Application" },
        new() { Name = "Microsoft-Windows-Sysmon/Operational" },
        // Script blocks only: 4103 (module logging) and the 4010x/5350x start-up chatter are noise.
        new() { Name = "Microsoft-Windows-PowerShell/Operational", Query = "*[System[(EventID=4104)]]" },
        // 1150/1151: hourly "running fine" health reports.
        new() { Name = "Microsoft-Windows-Windows Defender/Operational", Query = "*[System[(EventID!=1150 and EventID!=1151)]]" },
    ];
}

[JsonConverter(typeof(JsonStringEnumConverter<InputType>))]
public enum InputType
{
    SyslogUdp,
    SyslogTcp,
    SyslogTls,
    /// <summary>Tail log files (<see cref="InputConfig.Paths"/>).</summary>
    File,
    /// <summary>Splunk-compatible HTTP Event Collector (<see cref="InputConfig.Tokens"/>).</summary>
    Hec,
    /// <summary>Windows event logs (<see cref="InputConfig.Channels"/>); Windows agents only.</summary>
    WindowsEventLog,
}

[JsonConverter(typeof(JsonStringEnumConverter<MultilineMode>))]
public enum MultilineMode
{
    /// <summary>Every line is an event.</summary>
    None,
    /// <summary>Lines starting with a space or tab continue the previous event (stack traces).</summary>
    Indented,
    /// <summary>
    /// A line matching <see cref="InputConfig.MultilineStart"/> starts an event; other lines continue it
    /// (Asterisk's SIP packet logging, Java logs: <c>^\[\d{4}-</c>).
    /// </summary>
    Pattern,
}

public sealed class InputConfig
{
    public InputType Type { get; set; }
    public string BindAddress { get; set; } = "0.0.0.0";
    public int Port { get; set; }
    /// <summary>Dataset hint for everything on this input when no <see cref="SourceHint"/> matches.</summary>
    public string? Dataset { get; set; }

    /// <summary>File: absolute paths; <c>*</c> and <c>?</c> are allowed in the file name (<c>/var/log/app/*.log</c>).</summary>
    public List<string>? Paths { get; set; }
    /// <summary>File: the app name events carry (<c>process.name</c>); default is the file name.</summary>
    public string? App { get; set; }
    /// <summary>File: read files that already exist from the start, not just new lines. WindowsEventLog: read each log's existing events on first start.</summary>
    public bool FromBeginning { get; set; }
    public MultilineMode Multiline { get; set; }
    /// <summary>File, <see cref="MultilineMode.Pattern"/>: regular expression for the first line of an event.</summary>
    public string? MultilineStart { get; set; }

    /// <summary>HEC: tokens clients send as <c>Authorization: DGSIEM &lt;token&gt;</c>.</summary>
    public List<string>? Tokens { get; set; }
    /// <summary>WindowsEventLog: the logs to read; empty means <see cref="EventLogChannel.Defaults"/>.</summary>
    public List<EventLogChannel>? Channels { get; set; }

    /// <summary>HEC: HTTPS with the agent's certificate (issued by the DG SIEM CA) instead of plain HTTP.</summary>
    public bool Tls { get; set; }
}

/// <summary>Where the file input got to in one file, so a restart resumes instead of re-reading or skipping.</summary>
public sealed class FilePosition
{
    /// <summary>Hash of the first <see cref="FingerprintLength"/> bytes: tells a rotated (new) file from the same one.</summary>
    public string Fingerprint { get; set; } = string.Empty;
    public int FingerprintLength { get; set; }
    public long Offset { get; set; }
}

public sealed class SourceHint
{
    /// <summary>An IP (<c>192.168.1.1</c>) or CIDR (<c>10.20.0.0/16</c>).</summary>
    public required string Source { get; set; }
    public required string Dataset { get; set; }
}

/// <summary>AOT-safe JSON metadata shared by agent and server.</summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, WriteIndented = false)]
[JsonSerializable(typeof(EnrollRequest))]
[JsonSerializable(typeof(EnrollResponse))]
[JsonSerializable(typeof(RenewRequest))]
[JsonSerializable(typeof(RenewResponse))]
[JsonSerializable(typeof(AgentUpdateInfo))]
[JsonSerializable(typeof(AgentIngestBatch))]
[JsonSerializable(typeof(AgentConfig))]
[JsonSerializable(typeof(RawEnvelope))]
[JsonSerializable(typeof(Dictionary<string, FilePosition>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
public sealed partial class AgentJsonContext : JsonSerializerContext;
