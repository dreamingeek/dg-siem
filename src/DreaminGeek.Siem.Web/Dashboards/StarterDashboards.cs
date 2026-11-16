namespace DreaminGeek.Siem.Web.Dashboards;

/// <summary>
/// The starter dashboard that spans several sources (CrowdSec, authentik, Traefik/Pangolin, UniFi). Dashboards for one
/// source come with its integration pack (packs/).
/// </summary>
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
            P("Firewall blocks", "dataset=unifi.firewall event.type=denied | stats count()", PanelKind.Stat, 9, 0, 3, 2),
            P("Bans by scenario", "dataset=crowdsec.decision | timechart count() by rule.name", PanelKind.TimeBars, 0, 2, 7, 4),
            P("Bans by country", "dataset=crowdsec.decision | stats count() by source.geo.country_iso_code", PanelKind.Map, 7, 2, 5, 4),
            P("Failed logins by user and source", "dataset=authentik.event action=login_failed | stats count() by user, src | sort -count | head 20", PanelKind.Table, 0, 6, 6, 4),
            P("Top ban scenarios", "dataset=crowdsec.decision | top limit=10 rule.name", PanelKind.Bars, 6, 6, 6, 4),
            P("Logins by country", "dataset=authentik.event action=login | stats count() by source.geo.country_iso_code", PanelKind.Map, 0, 10, 6, 4),
            P("What scanners look for", "dataset=traefik.access action=unrouted | top limit=10 path", PanelKind.Bars, 6, 10, 6, 4),
            P("Scanners by country", "dataset=traefik.access action=unrouted | stats count() by country", PanelKind.Map, 0, 14, 6, 5),
            P("Scanner networks", "dataset=traefik.access action=unrouted | top limit=10 org", PanelKind.Bars, 6, 14, 6, 5),
        ]),
    ];
}
