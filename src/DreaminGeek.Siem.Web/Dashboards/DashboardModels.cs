using System.Text.Json;
using System.Text.Json.Serialization;

namespace DreaminGeek.Siem.Web.Dashboards;

public enum PanelKind
{
    /// <summary>Lines over time (<c>| timechart …</c>).</summary>
    TimeLine,
    /// <summary>Stacked areas over time.</summary>
    TimeArea,
    /// <summary>Bars over time, stacked when split by a field.</summary>
    TimeBars,
    /// <summary>One number, with the change since the previous period and a sparkline when possible.</summary>
    Stat,
    /// <summary>Horizontal bars ranking values (<c>| top …</c> or <c>| stats … by …</c>).</summary>
    Bars,
    Pie,
    Table,
    /// <summary>Countries shaded by value (<c>| stats count() by source.geo.country_iso_code</c>).</summary>
    Map,
}

public enum PanelUnit
{
    Number,
    /// <summary>Nanoseconds (ECS <c>event.duration</c>) shown as ms / s.</summary>
    Duration,
    Bytes,
    Percent,
}

/// <summary>One panel on a dashboard: its search, how it's drawn, and where it sits on the 12-column grid.</summary>
public sealed class DashboardPanel
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..10];
    public string Title { get; set; } = string.Empty;
    public string Query { get; set; } = string.Empty;
    public PanelKind Kind { get; set; } = PanelKind.TimeBars;
    public PanelUnit Unit { get; set; }
    public int X { get; set; }
    public int Y { get; set; }
    public int W { get; set; } = 6;
    public int H { get; set; } = 4;

    public DashboardPanel Clone() => (DashboardPanel)MemberwiseClone();

    /// <summary>A size that suits the kind, for newly added panels.</summary>
    public static (int W, int H) DefaultSize(PanelKind kind) => kind switch
    {
        PanelKind.Stat => (3, 2),
        PanelKind.Map => (6, 5),
        PanelKind.Pie => (4, 4),
        PanelKind.Table => (6, 4),
        PanelKind.Bars => (4, 4),
        _ => (8, 4),
    };

    public static string Describe(PanelKind kind) => kind switch
    {
        PanelKind.TimeLine => "Lines over time",
        PanelKind.TimeArea => "Stacked area over time",
        PanelKind.TimeBars => "Bars over time",
        PanelKind.Stat => "Single number",
        PanelKind.Bars => "Ranked bars",
        PanelKind.Pie => "Pie",
        PanelKind.Table => "Table",
        PanelKind.Map => "World map",
        _ => kind.ToString(),
    };

    /// <summary>What the search should end with for this kind.</summary>
    public static string Hint(PanelKind kind) => kind switch
    {
        PanelKind.TimeLine or PanelKind.TimeArea or PanelKind.TimeBars => "End the search with | timechart, e.g. | timechart count() by dataset",
        PanelKind.Stat => "End with | stats and one value, e.g. | stats count(). Shows the change from the previous period.",
        PanelKind.Bars or PanelKind.Pie => "End with | top or | stats … by, e.g. | top limit=10 src",
        PanelKind.Map => "End with | stats … by a 2-letter country code, e.g. | stats count() by source.geo.country_iso_code",
        _ => "Any search; the first 100 rows are shown.",
    };

    public static bool IsTimeKind(PanelKind kind) => kind is PanelKind.TimeLine or PanelKind.TimeArea or PanelKind.TimeBars;
}

public static class PanelJson
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public static string Serialize(IEnumerable<DashboardPanel> panels) => JsonSerializer.Serialize(panels, Options);

    public static List<DashboardPanel> Deserialize(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }
        try
        {
            return JsonSerializer.Deserialize<List<DashboardPanel>>(json, Options) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
