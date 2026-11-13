namespace DreaminGeek.Siem.Web.Agents;

public sealed class PkiOptions
{
    public const string SectionName = "Pki";

    /// <summary>Where the CA and agent-port certificate live. Persist and back this up: losing it means re-enrolling every agent.</summary>
    public string Directory { get; set; } = "/var/lib/dg-siem/pki";

    /// <summary>
    /// DNS names and IPs agents use to reach the agent port, e.g. <c>siem-agents.example.com</c>.
    /// Must match the agents' ServerUrl host, or TLS fails. Changing this re-issues the server certificate.
    /// </summary>
    public List<string> AgentHostnames { get; set; } = ["localhost"];

    public int AgentCertificateDays { get; set; } = 365;
    public int ServerCertificateDays { get; set; } = 397;
}
