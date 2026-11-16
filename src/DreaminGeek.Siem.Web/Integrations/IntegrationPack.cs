using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Web.Dashboards;
using System.Text.Json.Nodes;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace DreaminGeek.Siem.Web.Integrations;

/// <summary>
/// An integration pack: data only (no code) describing how to get one kind of source into DG SIEM and what to do
/// with it: setup steps and the agent input, how to tell data is arriving, dashboards and alerts. Read from
/// <c>pack.yaml</c> files (see docs/integrations.md).
/// </summary>
public sealed class IntegrationPack
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public int Version { get; set; } = 1;
    public string Category { get; set; } = "Other";
    public string Description { get; set; } = string.Empty;
    /// <summary>Optional link to the product's own documentation.</summary>
    public string? Docs { get; set; }
    public PackSetup Setup { get; set; } = new();
    public PackReceiving? Receiving { get; set; }
    public List<PackDashboard> Dashboards { get; set; } = [];
    public List<PackAlert> Alerts { get; set; } = [];

    /// <summary>Where it was read from: "built-in", or the file's path for packs from the packs folder.</summary>
    [YamlIgnore]
    public string Source { get; set; } = "built-in";

    [YamlIgnore]
    public bool BuiltIn => Source == "built-in";
}

public sealed class PackSetup
{
    /// <summary>
    /// The agent input to add, as in an agent's config. <c>{{token}}</c> is replaced with a token generated for
    /// each tenant. Optional: some sources only need a parser and an existing input (syslog).
    /// </summary>
    public Dictionary<string, object>? Input { get; set; }

    /// <summary><see cref="Input"/> as JSON, with numbers and booleans kept (set when the pack is read).</summary>
    [YamlIgnore]
    public string? InputJson { get; set; }

    /// <summary>What to do at the source, one step per item. <c>`code`</c>, <c>**bold**</c>, <c>{{token}}</c>, <c>{{port}}</c> and <c>{{tenant}}</c> work.</summary>
    public List<string> Steps { get; set; } = [];
}

public sealed class PackReceiving
{
    /// <summary>A search that returns rows when data is arriving, e.g. <c>| mstats count(cpustat_cpu)</c>.</summary>
    public string Search { get; set; } = string.Empty;

    /// <summary>How far back to look: <c>15m</c>, <c>1h</c>, <c>1d</c>.</summary>
    public string Within { get; set; } = "15m";
}

public sealed class PackDashboard
{
    /// <summary>Stable key within the pack, so a renamed dashboard is still recognized on upgrade.</summary>
    public string Key { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string TimeRange { get; set; } = "-24h";
    public List<PackPanel> Panels { get; set; } = [];
}

public sealed class PackPanel
{
    public string Title { get; set; } = string.Empty;
    public string Search { get; set; } = string.Empty;
    /// <summary>timeline, timearea, timebars, stat, bars, pie, table or map.</summary>
    public string Kind { get; set; } = "timeline";
    /// <summary>number, duration, bytes or percent.</summary>
    public string Unit { get; set; } = "number";
    /// <summary>Width on the 12-column grid; panels flow left to right, top to bottom.</summary>
    public int? W { get; set; }
    public int? H { get; set; }
    /// <summary>Optional fixed position (column 0-11, row); give both, or leave both out to flow.</summary>
    public int? X { get; set; }
    public int? Y { get; set; }
}

public sealed class PackAlert
{
    public string Key { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Search { get; set; } = string.Empty;
    /// <summary>How far back each run looks: <c>15m</c>, <c>1h</c>.</summary>
    public string TimeRange { get; set; } = "15m";
    public string Schedule { get; set; } = "*/5 * * * *";
    /// <summary><c>any</c> (any results), <c>above</c> or <c>below</c> (number of results vs <see cref="Threshold"/>).</summary>
    public string Condition { get; set; } = "any";
    public long Threshold { get; set; }
    /// <summary><c>once</c>, or <c>per-result</c> for one alert per row.</summary>
    public string Trigger { get; set; } = "once";
    public string Severity { get; set; } = "medium";
    public string? SuppressBy { get; set; }
    public int SuppressMinutes { get; set; } = 60;
}

/// <summary>Turning pack text into the dashboards and alert rules it creates.</summary>
public static partial class PackContent
{
    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    public static IntegrationPack Parse(string yaml)
    {
        var pack = Yaml.Deserialize<IntegrationPack>(yaml) ?? throw new PackException("The file is empty.");
        pack.Setup ??= new PackSetup();
        if (pack.Setup.Input is { Count: > 0 })
        {
            // Read the input again as YAML nodes: the typed read above turns every value into a string.
            var stream = new YamlStream();
            stream.Load(new StringReader(yaml));
            var root = (YamlMappingNode)stream.Documents[0].RootNode;
            var input = ((YamlMappingNode)root.Children[new YamlScalarNode("setup")]).Children[new YamlScalarNode("input")];
            pack.Setup.InputJson = ToJson(input)?.ToJsonString();
        }
        return pack;
    }

    private static JsonNode? ToJson(YamlNode node) => node switch
    {
        YamlMappingNode map => new JsonObject(map.Children.Select(c => KeyValuePair.Create(((YamlScalarNode)c.Key).Value ?? "", ToJson(c.Value)))),
        YamlSequenceNode list => new JsonArray(list.Children.Select(ToJson).ToArray()),
        YamlScalarNode { Style: ScalarStyle.Plain } plain => plain.Value switch
        {
            null or "" or "~" or "null" => null,
            "true" => JsonValue.Create(true),
            "false" => JsonValue.Create(false),
            var v when long.TryParse(v, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out var n) => JsonValue.Create(n),
            var v when double.TryParse(v, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) => JsonValue.Create(d),
            var v => JsonValue.Create(v),
        },
        YamlScalarNode scalar => JsonValue.Create(scalar.Value),
        _ => null,
    };

    /// <summary>The setup input as JSON with <c>{{token}}</c> filled in; null when the pack has none.</summary>
    public static string? InputJson(IntegrationPack pack, string token)
    {
        // The token is generated (URL-safe base64), so it needs no JSON escaping.
        return pack.Setup.InputJson?.Replace("{{token}}", token, StringComparison.Ordinal);
    }

    /// <summary>The port the setup input listens on, for the steps' <c>{{port}}</c>.</summary>
    public static string Port(IntegrationPack pack) =>
        pack.Setup.Input?.TryGetValue("port", out var port) == true ? Convert.ToString(port, System.Globalization.CultureInfo.InvariantCulture) ?? "" : "";

    public static PanelKind Kind(string kind) => kind.Trim().ToLowerInvariant() switch
    {
        "timeline" or "line" => PanelKind.TimeLine,
        "timearea" or "area" => PanelKind.TimeArea,
        "timebars" => PanelKind.TimeBars,
        "stat" => PanelKind.Stat,
        "bars" => PanelKind.Bars,
        "pie" => PanelKind.Pie,
        "table" => PanelKind.Table,
        "map" => PanelKind.Map,
        _ => throw new PackException($"Panel kind \"{kind}\" isn't one of timeline, timearea, timebars, stat, bars, pie, table, map."),
    };

    public static PanelUnit Unit(string unit) => unit.Trim().ToLowerInvariant() switch
    {
        "" or "number" => PanelUnit.Number,
        "duration" => PanelUnit.Duration,
        "bytes" => PanelUnit.Bytes,
        "percent" => PanelUnit.Percent,
        _ => throw new PackException($"Panel unit \"{unit}\" isn't one of number, duration, bytes, percent."),
    };

    public static AlertCondition Condition(string condition) => condition.Trim().ToLowerInvariant() switch
    {
        "any" or "" => AlertCondition.AnyResults,
        "above" => AlertCondition.CountGreaterThan,
        "below" => AlertCondition.CountLessThan,
        _ => throw new PackException($"Alert condition \"{condition}\" isn't one of any, above, below."),
    };

    public static AlertTrigger Trigger(string trigger) => trigger.Trim().ToLowerInvariant() switch
    {
        "once" or "" => AlertTrigger.Once,
        "per-result" or "perresult" => AlertTrigger.PerResult,
        _ => throw new PackException($"Alert trigger \"{trigger}\" isn't once or per-result."),
    };

    public static AlertSeverity Severity(string severity) =>
        Enum.TryParse<AlertSeverity>(severity.Trim(), ignoreCase: true, out var s) && Enum.IsDefined(s)
            ? s
            : throw new PackException($"Alert severity \"{severity}\" isn't one of {string.Join(", ", Enum.GetNames<AlertSeverity>()).ToLowerInvariant()}.");

    /// <summary>The panels laid out on the 12-column grid: left to right, wrapping, each row as tall as its tallest panel.</summary>
    public static List<DashboardPanel> Panels(PackDashboard dashboard)
    {
        var panels = new List<DashboardPanel>();
        int x = 0, y = 0, rowHeight = 0;
        for (var i = 0; i < dashboard.Panels.Count; i++)
        {
            var p = dashboard.Panels[i];
            var kind = Kind(p.Kind);
            var (dw, dh) = DashboardPanel.DefaultSize(kind);
            var w = Math.Clamp(p.W ?? dw, 1, 12);
            var h = Math.Clamp(p.H ?? dh, 1, 12);
            if (p.X is { } fixedX && p.Y is { } fixedY)
            {
                panels.Add(Panel(dashboard.Key, i, p, kind, Math.Clamp(fixedX, 0, 12 - w), Math.Max(0, fixedY), w, h));
                continue;
            }
            if (x + w > 12)
            {
                x = 0;
                y += rowHeight;
                rowHeight = 0;
            }
            panels.Add(Panel(dashboard.Key, i, p, kind, x, y, w, h));
            x += w;
            rowHeight = Math.Max(rowHeight, h);
        }
        return panels;
    }

    private static DashboardPanel Panel(string key, int i, PackPanel p, PanelKind kind, int x, int y, int w, int h) =>
        new()
        {
            Id = $"{key}-{i}",
            Title = p.Title.Trim(),
            Query = p.Search.Trim(),
            Kind = kind,
            Unit = Unit(p.Unit),
            X = x,
            Y = y,
            W = w,
            H = h,
        };

    /// <summary>
    /// Fingerprint of what a pack wrote into a dashboard, to tell later whether someone edited it. Panel ids are
    /// internal (a dashboard made by hand has random ones), so they don't count.
    /// </summary>
    public static string Hash(Dashboard d)
    {
        // Re-serialized: Postgres stores the layout as jsonb, which doesn't keep the text as written.
        var panels = PanelJson.Deserialize(d.LayoutJson);
        panels.ForEach(p => p.Id = string.Empty);
        return Sha(string.Join('\u001f', d.Name, d.Description ?? "", d.TimeRange, PanelJson.Serialize(panels)));
    }

    /// <summary>The fingerprint as the first version (0.7.0) computed it, with panel ids.</summary>
    private static string HashWithIds(Dashboard d) =>
        Sha(string.Join('\u001f', d.Name, d.Description ?? "", d.TimeRange, PanelJson.Serialize(PanelJson.Deserialize(d.LayoutJson))));

    /// <summary>Whether the dashboard is still as its pack wrote it.</summary>
    public static bool Untouched(Dashboard d) => d.PackHash is { } h && (h == Hash(d) || h == HashWithIds(d));

    /// <summary>Whether the alert rule is still as its pack wrote it.</summary>
    public static bool Untouched(AlertRule r) => r.PackHash is { } h && h == Hash(r);

    /// <summary>
    /// Fingerprint of an alert rule's definition. Whether it's on, and who it emails or tickets, are the user's
    /// choices and don't count as edits.
    /// </summary>
    public static string Hash(AlertRule r) => Sha(string.Join('\u001f',
        r.Name, r.Description ?? "", r.Query, r.TimeRange, r.Schedule, (int)r.Condition, r.Threshold, (int)r.Trigger, (int)r.Severity,
        r.SuppressBy ?? "", (long)r.SuppressFor.TotalMinutes));

    private static string Sha(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..32];

    /// <summary>Step text as HTML: encoded, with <c>`code`</c> and <c>**bold**</c>, and the placeholders filled.</summary>
    public static string StepHtml(string step, IReadOnlyDictionary<string, string> values)
    {
        var html = System.Net.WebUtility.HtmlEncode(step);
        html = CodeSpan().Replace(html, "<code>$1</code>");
        html = BoldSpan().Replace(html, "<strong>$1</strong>");
        return Placeholder().Replace(html, m => values.TryGetValue(m.Groups[1].Value, out var v)
            ? $"<code class=\"dg-pack-value\">{System.Net.WebUtility.HtmlEncode(v)}</code>"
            : m.Value);
    }

    [GeneratedRegex("`([^`]+)`")]
    private static partial Regex CodeSpan();

    [GeneratedRegex(@"\*\*([^*]+)\*\*")]
    private static partial Regex BoldSpan();

    [GeneratedRegex(@"\{\{(\w+)\}\}")]
    internal static partial Regex Placeholder();
}

public sealed class PackException(string message) : Exception(message);
