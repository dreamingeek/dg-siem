namespace DreaminGeek.Siem.Web.Dashboards;

/// <summary>Ready-made dashboards for the sources DG SIEM parses (CrowdSec, authentik, Traefik/Pangolin, UniFi).</summary>
public static class StarterDashboards
{
    public sealed record Starter(string Name, string Description, string TimeRange, Func<List<DashboardPanel>> Panels);

    private static DashboardPanel P(string title, string query, PanelKind kind, int x, int y, int w, int h, PanelUnit unit = PanelUnit.Number) =>
        new() { Title = title, Query = query, Kind = kind, X = x, Y = y, W = w, H = h, Unit = unit };

    public static readonly IReadOnlyList<Starter> All =
    [
        new("Security overview", "Bans, failed logins, scanners and firewall blocks across every tenant.", "-24h", () =>
        [
            P("CrowdSec bans", "dataset=crowdsec.decision | stats count()", PanelKind.Stat, 0, 0, 3, 2),
            P("Failed logins", "dataset=authentik.event action=login_failed | stats count()", PanelKind.Stat, 3, 0, 3, 2),
            P("Scanner requests", "dataset=traefik.access action=unrouted | stats count()", PanelKind.Stat, 6, 0, 3, 2),
            P("Firewall blocks", "dataset=unifi.firewall action=blocked | stats count()", PanelKind.Stat, 9, 0, 3, 2),
            P("Bans by scenario", "dataset=crowdsec.decision | timechart count() by rule.name", PanelKind.TimeBars, 0, 2, 7, 4),
            P("Bans by country", "dataset=crowdsec.decision | stats count() by source.geo.country_iso_code", PanelKind.Map, 7, 2, 5, 4),
            P("Failed logins by user and source", "dataset=authentik.event action=login_failed | stats count() by user, src | sort -count | head 20", PanelKind.Table, 0, 6, 6, 4),
            P("Top ban scenarios", "dataset=crowdsec.decision | top limit=10 rule.name", PanelKind.Bars, 6, 6, 6, 4),
            P("Logins by country", "dataset=authentik.event action=login | stats count() by source.geo.country_iso_code", PanelKind.Map, 0, 10, 6, 4),
            P("What scanners look for", "dataset=traefik.access action=unrouted | top limit=10 path", PanelKind.Bars, 6, 10, 6, 4),
            P("Scanners by country", "dataset=traefik.access action=unrouted | stats count() by country", PanelKind.Map, 0, 14, 6, 5),
            P("Scanner networks", "dataset=traefik.access action=unrouted | top limit=10 org", PanelKind.Bars, 6, 14, 6, 5),
        ]),
        new("Pangolin traffic", "Requests through Traefik/Pangolin: volume, errors, latency and clients.", "-24h", () =>
        [
            P("Requests", "dataset=traefik.access | stats count()", PanelKind.Stat, 0, 0, 3, 2),
            P("Server errors (5xx)", "dataset=traefik.access status>=500 | stats count()", PanelKind.Stat, 3, 0, 3, 2),
            P("Client errors (4xx)", "dataset=traefik.access status>=400 status<500 | stats count()", PanelKind.Stat, 6, 0, 3, 2),
            P("p95 response time", "dataset=traefik.access action=proxied | stats p95(event.duration)", PanelKind.Stat, 9, 0, 3, 2, PanelUnit.Duration),
            P("Requests by resource", "dataset=traefik.access action=proxied | timechart count() by resource", PanelKind.TimeArea, 0, 2, 8, 4),
            P("Top resources", "dataset=traefik.access action=proxied | top limit=10 resource", PanelKind.Bars, 8, 2, 4, 4),
            P("Errors by status", "dataset=traefik.access status>=400 | timechart count() by status", PanelKind.TimeBars, 0, 6, 8, 4),
            P("Status codes", "dataset=traefik.access | top limit=8 status", PanelKind.Pie, 8, 6, 4, 4),
            P("Top clients", "dataset=traefik.access | stats count() as requests by src | sort -requests | head 15", PanelKind.Table, 0, 10, 6, 4),
            P("Slowest resources (p95)", "dataset=traefik.access action=proxied | stats p95(event.duration) as p95 by resource | sort -p95 | head 10", PanelKind.Bars, 6, 10, 6, 4, PanelUnit.Duration),
            P("Requests by country", "dataset=traefik.access | stats count() by country", PanelKind.Map, 0, 14, 6, 5),
            P("Top client networks", "dataset=traefik.access | top limit=10 org", PanelKind.Bars, 6, 14, 6, 5),
        ]),
        new("UniFi firewall", "Firewall blocks per tenant, rule, source and port.", "-24h", () =>
        [
            P("Blocked", "dataset=unifi.firewall action=blocked | stats count()", PanelKind.Stat, 0, 0, 3, 2),
            P("Blocked sources", "dataset=unifi.firewall action=blocked | stats dc(src)", PanelKind.Stat, 3, 0, 3, 2),
            P("Firewall events", "dataset=unifi.firewall | stats count()", PanelKind.Stat, 6, 0, 3, 2),
            P("UniFi events", "dataset=unifi* | stats count()", PanelKind.Stat, 9, 0, 3, 2),
            P("Blocks by tenant", "dataset=unifi.firewall action=blocked | timechart count() by tenant", PanelKind.TimeBars, 0, 2, 8, 4),
            P("Top rules", "dataset=unifi.firewall | top limit=10 rule.name", PanelKind.Bars, 8, 2, 4, 4),
            P("Top blocked sources", "dataset=unifi.firewall action=blocked | top limit=10 src", PanelKind.Bars, 0, 6, 4, 4),
            P("Blocked destination ports", "dataset=unifi.firewall action=blocked | stats count() by dport, proto | sort -count | head 15", PanelKind.Table, 4, 6, 4, 4),
            P("UniFi events by dataset", "dataset=unifi* | timechart count() by dataset", PanelKind.TimeLine, 8, 6, 4, 4),
            P("Blocked by country", "dataset=unifi.firewall action=blocked | stats count() by country", PanelKind.Map, 0, 10, 6, 5),
            P("Top blocked networks", "dataset=unifi.firewall action=blocked | top limit=10 org", PanelKind.Bars, 6, 10, 6, 5),
        ]),
    ];
}
