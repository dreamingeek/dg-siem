using System.Text.Json;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Dashboards;

namespace DreaminGeek.Siem.Tests;

public class DashboardTests
{
    private static readonly PipeParser Parser = new();

    private static QueryResult Result(string[] columns, params object?[][] rows) =>
        new(columns, rows, ResultShape.Table, false, TimeSpan.Zero);

    [Theory]
    [InlineData("dataset=crowdsec.decision | stats count()", "dataset=crowdsec.decision | timechart count()")]
    [InlineData("dataset=traefik.access action=proxied | stats p95(event.duration)", "dataset=traefik.access action=proxied | timechart p95(event.duration)")]
    [InlineData("x | STATS dc(src) as n", "x | timechart dc(src) as n")]
    public void StatSparklineIsTheSameSearchOverTime(string query, string expected) =>
        Assert.Equal(expected, PanelData.SparklineQuery(query, Parser));

    [Theory]
    [InlineData("dataset=x | stats count() by src")]
    [InlineData("dataset=x | stats count() | eval y = count * 2")]
    [InlineData("dataset=x")]
    [InlineData("| broken (")]
    public void NoSparklineWhenItCantBeDerived(string query) =>
        Assert.Null(PanelData.SparklineQuery(query, Parser));

    [Fact]
    public void ItemsUseTextLabelsAndTheFirstNumber()
    {
        // top output: value, count, percent → the count is plotted, not the percent.
        var items = PanelData.Items(Result(["rule.name", "count", "percent"],
            ["crowdsecurity/http-probing", 120UL, 60.0], ["crowdsecurity/ssh-bf", 80UL, 40.0]));
        Assert.Equal([new PanelItem("crowdsecurity/http-probing", 120), new PanelItem("crowdsecurity/ssh-bf", 80)], items);

        var twoKeys = PanelData.Items(Result(["user.name", "source.ip", "count"], ["admin", "198.51.100.23", 7UL], ["", "203.0.113.5", 2UL]));
        Assert.Equal("admin / 198.51.100.23", twoKeys[0].Name);
        Assert.Equal("(empty) / 203.0.113.5", twoKeys[1].Name);
    }

    [Fact]
    public void MapKeepsOnlyCountryCodes()
    {
        var items = new List<PanelItem> { new("US", 5), new("nl", 3), new("", 9), new("Unknown", 1), new("NL", 2) };
        var json = JsonSerializer.Serialize(PanelData.Map(items));
        Assert.Contains("\"name\":\"US\",\"value\":5", json, StringComparison.Ordinal);
        Assert.Contains("\"name\":\"NL\",\"value\":5", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Unknown", json, StringComparison.Ordinal);
        Assert.Contains("\"max\":5", json, StringComparison.Ordinal);
    }

    [Fact]
    public void PieGroupsTheTailIntoOther()
    {
        var items = Enumerable.Range(1, 12).Select(i => new PanelItem($"v{i}", i)).ToList();
        var json = JsonSerializer.Serialize(PanelData.Pie(items));
        Assert.Contains("\"name\":\"v12\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"name\":\"v4\"", json, StringComparison.Ordinal);
        Assert.Contains("\"name\":\"Other\",\"value\":10", json, StringComparison.Ordinal); // 1+2+3+4
    }

    [Fact]
    public void StatTakesTheFirstNumber()
    {
        Assert.Equal(42, PanelData.Stat(Result(["count"], [42UL])));
        Assert.Null(PanelData.Stat(Result(["count"])));
    }

    [Theory]
    [InlineData(1234.0, PanelUnit.Number, "1,234")]
    [InlineData(48200.0, PanelUnit.Number, "48.2k")]
    [InlineData(2500000.0, PanelUnit.Number, "2.5M")]
    [InlineData(287504981.0, PanelUnit.Duration, "287.5 ms")]
    [InlineData(1450000000.0, PanelUnit.Duration, "1.45 s")]
    [InlineData(4326.0, PanelUnit.Bytes, "4.2 KB")]
    [InlineData(12.34, PanelUnit.Percent, "12.3%")]
    public void FormatsUnits(double value, PanelUnit unit, string expected) =>
        Assert.Equal(expected, PanelData.Format(value, unit));

    [Theory]
    [InlineData(120.0, 100.0, "+20%")]
    [InlineData(50.0, 100.0, "−50%")]
    [InlineData(5.0, 0.0, "new")]
    [InlineData(0.0, 0.0, "no change")]
    [InlineData(1956.0, 1.0, "1956×")]
    public void ChangeAgainstThePreviousPeriod(double value, double previous, string expected) =>
        Assert.Equal(expected, PanelData.Change(value, previous));

    [Fact]
    public void PanelsRoundTripAsJson()
    {
        var panels = new List<DashboardPanel> { new() { Title = "Bans", Query = "dataset=crowdsec.decision | stats count()", Kind = PanelKind.Stat, Unit = PanelUnit.Number, X = 3, Y = 0, W = 3, H = 2 } };
        var json = PanelJson.Serialize(panels);
        Assert.Contains("\"kind\":\"Stat\"", json, StringComparison.Ordinal);
        var back = Assert.Single(PanelJson.Deserialize(json));
        Assert.Equal((3, 0, 3, 2, PanelKind.Stat), (back.X, back.Y, back.W, back.H, back.Kind));
        Assert.Empty(PanelJson.Deserialize("not json"));
    }

    [Fact]
    public void StarterDashboardsAreValidAndFitTheGrid()
    {
        foreach (var starter in StarterDashboards.All)
        {
            var panels = starter.Panels();
            Assert.NotEmpty(panels);
            Assert.Equal(panels.Count, panels.Select(p => p.Id).Distinct().Count());
            foreach (var p in panels)
            {
                Parser.Parse(p.Query);
                Assert.InRange(p.X + p.W, 1, 12);
                if (DashboardPanel.IsTimeKind(p.Kind))
                {
                    Assert.Contains("timechart", p.Query, StringComparison.Ordinal);
                }
                if (p.Kind == PanelKind.Stat)
                {
                    Assert.NotNull(PanelData.SparklineQuery(p.Query, Parser));
                }
            }
            // No two panels overlap.
            var cells = new HashSet<(int, int)>();
            foreach (var p in panels)
            {
                for (var x = p.X; x < p.X + p.W; x++)
                {
                    for (var y = p.Y; y < p.Y + p.H; y++)
                    {
                        Assert.True(cells.Add((x, y)), $"{starter.Name}: \"{p.Title}\" overlaps at {x},{y}");
                    }
                }
            }
        }
    }
}
