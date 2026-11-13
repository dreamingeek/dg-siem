using DreaminGeek.Siem.Data.Entities;

namespace DreaminGeek.Siem.Web.Alerts;

/// <summary>
/// Ready-made security alerts for the sources DG SIEM parses: Windows sign-ins and changes, Defender, the PBXs,
/// authentik, and the pipeline itself. Added from the Alerts page; each runs for every tenant separately, emails
/// the admin who added it, and opens a ticket when it's High or Critical. Thresholds are set to stay quiet on
/// normal traffic; tune them in the editor like any other alert.
/// </summary>
public static class SecurityAlerts
{
    public sealed record Template(
        string Group, string Name, string Description, string Query, AlertSeverity Severity,
        string TimeRange = "15m", string Schedule = "*/5 * * * *",
        AlertCondition Condition = AlertCondition.AnyResults, long Threshold = 0,
        AlertTrigger Trigger = AlertTrigger.PerResult, string? SuppressBy = null, int SuppressMinutes = 60,
        AlertRuleKind Kind = AlertRuleKind.Search);

    public const string Windows = "Windows sign-ins and changes";
    public const string Defender = "Microsoft Defender";
    public const string Pbx = "Phone systems";
    public const string Identity = "authentik and the pipeline";
    public const string Health = "Health: agents and log sources";
    public const string ThreatIntel = "Threat intel";

    /// <summary>Private, CGNAT, loopback, link-local and unique-local ranges: anything else is the internet.</summary>
    private const string NotInternal =
        "NOT src=10.0.0.0/8 NOT src=172.16.0.0/12 NOT src=192.168.0.0/16 NOT src=100.64.0.0/10 NOT src=127.0.0.0/8 NOT src=169.254.0.0/16 " +
        "NOT src=::1 NOT src=fe80::/10 NOT src=fc00::/7";

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
            "An agent stopped checking in (30 minutes), or events have waited in its buffer for over 30 minutes without getting through.",
            string.Empty, AlertSeverity.High, Schedule: "*/5 * * * *", Trigger: AlertTrigger.Once, SuppressMinutes: 12 * 60,
            Kind: AlertRuleKind.AgentProblems),

        // ---- Windows -------------------------------------------------------------------------
        new(Windows, "Windows: repeated failed sign-ins from one source",
            "20 or more failed sign-ins, or 5 or more different accounts tried, from one address in 15 minutes: password guessing or spraying.",
            "dataset=windows.security action=logon-failed src=* | stats count() as tries, dc(user) as accounts, dc(host) as hosts by src, country | where tries >= 20 OR accounts >= 5",
            AlertSeverity.High, SuppressBy: "source.ip"),
        new(Windows, "Windows: account locked out",
            "An account was locked out after too many bad passwords. from_computer is where the attempts came from.",
            "dataset=windows.security action=locked-out-user-account | stats count() as lockouts, latest(source.domain) as from_computer by user, host",
            AlertSeverity.Medium, SuppressBy: "user.name"),
        new(Windows, "Windows: added to a privileged group",
            "Someone was added to Administrators, Domain/Enterprise/Schema Admins, Account or Backup Operators, Remote Desktop Users or DnsAdmins.",
            "dataset=windows.security action=added-member-to-group group.name IN (\"Administrators\", \"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\", \"Account Operators\", \"Backup Operators\", \"Remote Desktop Users\", \"DnsAdmins\") | table @timestamp, host, user, user.target.name, group.name",
            AlertSeverity.High, SuppressBy: "host.name,user.target.name,group.name"),
        new(Windows, "Windows: new user account",
            "A local or domain account was created. user is who created it, user.target.name the new account.",
            "dataset=windows.security action=added-user-account | table @timestamp, host, user, user.target.name",
            AlertSeverity.Medium, SuppressBy: "host.name,user.target.name"),
        new(Windows, "Windows: security or event log cleared",
            "The Security log (1102) or another event log (104) was cleared: a common step to hide what happened.",
            "dataset=windows.* action IN (audit-log-cleared, log-cleared) | table @timestamp, host, user, winlog.channel",
            AlertSeverity.Critical, SuppressBy: "host.name,winlog.channel"),
        new(Windows, "Windows: remote desktop sign-in from the internet",
            "A successful Remote Desktop sign-in from a public address. Expected ones (a VPN's public IP) can be excluded in the search.",
            $"dataset=windows.security action=logged-in winlog.logon.type=RemoteInteractive src=* {NotInternal} | stats count() as signins by user, src, country, host",
            AlertSeverity.High, SuppressBy: "user.name,source.ip", SuppressMinutes: 12 * 60),
        new(Windows, "Windows: new service installed",
            "A service was installed (7045/4697). Software updates do this too; PsExec, remote-access tools and odd paths are what to look for.",
            "dataset=windows.* action=service-installed | table @timestamp, host, user, service.name, process.executable",
            AlertSeverity.Medium, SuppressBy: "host.name,service.name", SuppressMinutes: 24 * 60),

        // ---- Defender ------------------------------------------------------------------------
        new(Defender, "Defender: malware detected",
            "Microsoft Defender detected malware or suspicious behaviour. defender.action shows what it did (quarantine, remove...).",
            "dataset=windows.defender action IN (malware-detected, suspicious-behavior-detected) | table @timestamp, host, user, action, threat.name, defender.severity, file.path, defender.action",
            AlertSeverity.High, SuppressBy: "host.name,threat.name"),
        new(Defender, "Defender: couldn't remove malware",
            "Defender detected a threat but its action failed: the malware may still be active.",
            "dataset=windows.defender action=malware-action-failed | table @timestamp, host, user, threat.name, file.path, defender.error",
            AlertSeverity.Critical, SuppressBy: "host.name,threat.name"),
        new(Defender, "Defender: protection turned off",
            "Real-time, virus or spyware protection was disabled, or tamper protection blocked an attempt to change it.",
            "dataset=windows.defender action IN (real-time-protection-disabled, virus-scanning-disabled, spyware-scanning-disabled, tamper-protection-blocked-change) | table @timestamp, host, user, action",
            AlertSeverity.Critical, SuppressBy: "host.name,event.action"),
        new(Defender, "Defender: signature updates failing",
            "Defender couldn't update its signatures in the last 4 hours.",
            "dataset=windows.defender action=signature-update-failed | stats count() as failures, latest(defender.error) as error by host",
            AlertSeverity.Medium, TimeRange: "4h", Schedule: "0 */4 * * *", SuppressBy: "host.name", SuppressMinutes: 24 * 60),

        // ---- PBX -----------------------------------------------------------------------------
        new(Pbx, "PBX: SIP brute force",
            "50 or more failed SIP registrations or calls from one address in 15 minutes against FreePBX or FusionPBX. Internet-facing PBXs see scanning all the time; this is the heavy end.",
            "dataset IN (asterisk.security, freeswitch.security) outcome=failure | stats count() as tries, dc(user) as extensions by src, country, host | where tries >= 50",
            AlertSeverity.Medium, SuppressBy: "source.ip", SuppressMinutes: 6 * 60),
        new(Pbx, "PBX: SIP trunk not registering",
            "The SIP trunk failed to register or answer pings 3 or more times in 15 minutes: outside calls may not work.",
            "(dataset=freeswitch.registration action IN (gateway-ping-failed, gateway-registration-failed)) OR (dataset=asterisk.log log.origin.file.name=res_pjsip_outbound_registration.c level IN (warning, error)) | stats count() as failures by host | where failures >= 3",
            AlertSeverity.High, SuppressBy: "host.name", SuppressMinutes: 2 * 60),

        // ---- authentik and the pipeline ------------------------------------------------------
        new(Identity, "authentik: repeated failed logins",
            "10 or more failed logins, or 5 or more accounts tried, from one address in 15 minutes.",
            "dataset=authentik.event action=login_failed | stats count() as tries, dc(user) as accounts by src, country | where tries >= 10 OR accounts >= 5",
            AlertSeverity.High, SuppressBy: "source.ip"),
        new(Identity, "No logs from a tenant",
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
