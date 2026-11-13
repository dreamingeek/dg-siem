namespace DreaminGeek.Siem.Agent;

/// <summary>
/// Local agent settings (<c>/etc/dg-siem-agent/appsettings.json</c>, on Windows
/// <c>%ProgramData%\DG SIEM\Agent\appsettings.json</c>). Inputs and source hints are
/// not configured here: they are pulled from the server so every site uses the same template.
/// </summary>
public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    /// <summary>DG SIEM agent endpoint, e.g. <c>https://siem-agents.example.com:8443</c>.</summary>
    public Uri? ServerUrl { get; set; }

    /// <summary>One-time enrollment token. Only used when the agent is not enrolled yet.</summary>
    public string? EnrollmentToken { get; set; }

    /// <summary>Agent name, e.g. <c>acme-log-col</c>. Defaults to the machine name.</summary>
    public string? Name { get; set; }

    /// <summary>Holds the agent key/certificate, cached config and the disk buffer.</summary>
    public string DataDirectory { get; set; } = DefaultDataDirectory;

    /// <summary><c>/var/lib/dg-siem-agent</c>, or <c>%ProgramData%\DG SIEM\Agent</c> on Windows (SYSTEM and Administrators only).</summary>
    public static string DefaultDataDirectory => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DG SIEM", "Agent")
        : "/var/lib/dg-siem-agent";

    /// <summary>The machine-wide settings file the service reads.</summary>
    public static string SystemSettingsPath => OperatingSystem.IsWindows()
        ? Path.Combine(DefaultDataDirectory, "appsettings.json")
        : "/etc/dg-siem-agent/appsettings.json";

    /// <summary>Sent at enrollment so the server gives a new agent the right default inputs.</summary>
    public static string Platform => OperatingSystem.IsWindows() ? "windows" : "linux";

    /// <summary>Disk buffer cap. When the server is unreachable this long, the oldest data is dropped first.</summary>
    public long MaxBufferBytes { get; set; } = 2L * 1024 * 1024 * 1024;

    /// <summary>Events per segment file (and per HTTP batch).</summary>
    public int MaxEventsPerSegment { get; set; } = 5000;

    /// <summary>Seal the open segment at least this often so data ships promptly.</summary>
    public TimeSpan SegmentMaxAge { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Renew the certificate when it has fewer than this many days left.</summary>
    public int RenewBeforeDays { get; set; } = 30;
}
