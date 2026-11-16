using DreaminGeek.Siem.Data.Entities;

namespace DreaminGeek.Siem.Web.Alerts;

/// <summary>
/// Ready-made alerts that aren't about one kind of source: threat intel matches, health, and a tenant going
/// silent. Added from the Alerts page (health ones also from the Health page); each runs for every tenant
/// separately, emails the admin who added it, and opens a ticket when it's High or Critical. Alerts for a
/// particular source (Windows, Defender, the PBXs, authentik, UniFi...) come with its integration pack (packs/).
/// </summary>
public static class SecurityAlerts
{
    public sealed record Template(
        string Group, string Name, string Description, string Query, AlertSeverity Severity,
        string TimeRange = "15m", string Schedule = "*/5 * * * *",
        AlertCondition Condition = AlertCondition.AnyResults, long Threshold = 0,
        AlertTrigger Trigger = AlertTrigger.PerResult, string? SuppressBy = null, int SuppressMinutes = 60,
        AlertRuleKind Kind = AlertRuleKind.Search);

    public const string Pipeline = "The pipeline";
    public const string Health = "Health: agents and log sources";
    public const string ThreatIntel = "Threat intel";

    public static readonly IReadOnlyList<Template> All =
    [
        // ---- Threat intel (offered when it's switched on under Features) ----------------------
        new(ThreatIntel, "Traffic to a known-bad address",
            "A device reached out (or tried to) to an address on a threat feed or your list: a botnet controller, a criminal network. Even blocked attempts mean something inside is trying.",
            "threat_on=destination.ip | stats count() as events by src, dst, dport, threat_feed, threat_reason, host",
            AlertSeverity.High, SuppressBy: "source.ip,destination.ip", SuppressMinutes: 12 * 60),
        new(ThreatIntel, "Sign-in from a known-bad address",
            "A successful sign-in (Windows, authentik, the PBX) from an address on a threat feed or your list. Tor exit nodes count when that feed is on.",
            "event.category=authentication outcome=success threat_on=source.ip | stats count() as signins by user, src, threat_feed, threat_reason, dataset, host",
            AlertSeverity.Critical, SuppressBy: "user.name,source.ip", SuppressMinutes: 12 * 60),

        // ---- Health --------------------------------------------------------------------------
        new(Health, "A log source went quiet",
            "A host stopped sending a dataset for longer than it usually goes silent (judged on its own last 8 days). One alert per tenant lists every quiet source. Retired sources can be ignored on the Health page.",
            string.Empty, AlertSeverity.High, Schedule: "*/15 * * * *", Trigger: AlertTrigger.Once, SuppressMinutes: 24 * 60,
            Kind: AlertRuleKind.QuietSources),
        new(Health, "An agent is offline or falling behind",
            "An agent stopped checking in (30 minutes), events have waited in its buffer for over 30 minutes without getting through, or a Prometheus target it scrapes stopped answering.",
            string.Empty, AlertSeverity.High, Schedule: "*/5 * * * *", Trigger: AlertTrigger.Once, SuppressMinutes: 12 * 60,
            Kind: AlertRuleKind.AgentProblems),

        // ---- The pipeline --------------------------------------------------------------------
        new(Pipeline, "No logs from a tenant",
            "A tenant sent no events at all in the last hour: a collector, agent or forwarding is down. Disable it for tenants that aren't sending logs yet.",
            "* | stats count() as events",
            AlertSeverity.High, TimeRange: "1h", Schedule: "*/15 * * * *", Condition: AlertCondition.CountLessThan, Threshold: 1,
            Trigger: AlertTrigger.Once, SuppressMinutes: 4 * 60),
    ];

    /// <summary>The alert as it's added: every tenant, email to <paramref name="emailTo"/>, tickets for High and Critical.</summary>
    public static AlertRuleForm ToForm(Template template, string? emailTo, bool enabled = true)
    {
        ArgumentNullException.ThrowIfNull(template);
        return new AlertRuleForm
        {
            Kind = template.Kind,
            Name = template.Name,
            Description = template.Description,
            Query = template.Query,
            Tenant = string.Empty,
            TimeRange = template.TimeRange,
            Schedule = template.Schedule,
            Condition = template.Condition,
            Threshold = template.Threshold,
            Trigger = template.Trigger,
            Severity = template.Severity,
            SuppressBy = template.SuppressBy,
            SuppressMinutes = template.SuppressMinutes,
            EmailTo = string.IsNullOrWhiteSpace(emailTo) ? null : emailTo,
            CreateTicket = template.Severity >= AlertSeverity.High,
            Enabled = enabled,
        };
    }
}
