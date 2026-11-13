using System.Globalization;
using DreaminGeek.Siem.Query;

namespace DreaminGeek.Siem.Web.Dashboards;

/// <summary>A label and number, for ranked bars, pies and the map.</summary>
public sealed record PanelItem(string Name, double Value);

/// <summary>What a panel shows after its search ran. Exactly one of the shape-specific parts is set.</summary>
public sealed class PanelResult
{
    public string? Error { get; init; }
    /// <summary>Data for the chart script (time series, items, map).</summary>
    public object? Chart { get; init; }
    public double? Value { get; init; }
    public double? Previous { get; init; }
    public object? Spark { get; init; }
    public IReadOnlyList<string> Columns { get; init; } = [];
    public IReadOnlyList<IReadOnlyList<string>> Rows { get; init; } = [];
    public IReadOnlySet<int> NumericColumns { get; init; } = new HashSet<int>();
    public bool Empty { get; init; }
    public TimeSpan Elapsed { get; init; }
}

/// <summary>Turns query results into panel data. Pure functions, so they're unit-tested without a database.</summary>
public static class PanelData
{
    public const int TableRows = 100;
    public const int BarItems = 15;
    public const int PieSlices = 8;

    /// <summary>Timechart rows (<c>_time</c>, optional split value, values) → chart series.</summary>
    public static object Timechart(QueryResult r, string kind = "bars")
    {
        ArgumentNullException.ThrowIfNull(r);
        var hasBy = r.Columns.Count >= 3 && r.Rows.Any(row => row[1] is string);
        var valueColumns = Enumerable.Range(hasBy ? 2 : 1, Math.Max(0, r.Columns.Count - (hasBy ? 2 : 1))).ToList();
        var series = new Dictionary<string, List<double?[]>>(StringComparer.Ordinal);
        foreach (var row in r.Rows)
        {
            if (row[0] is not DateTime time)
            {
                continue;
            }
            var ms = new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
            var group = hasBy ? (row[1] as string is { Length: > 0 } g ? g : "(none)") : null;
            foreach (var i in valueColumns)
            {
                var name = group is null ? r.Columns[i] : valueColumns.Count == 1 ? group : $"{r.Columns[i]}: {group}";
                if (!series.TryGetValue(name, out var points))
                {
                    series[name] = points = [];
                }
                points.Add([ms, Number(row[i])]);
            }
        }
        return new
        {
            kind,
            stacked = hasBy && valueColumns.Count == 1,
            series = series.Select(s => new { name = s.Key, points = s.Value }).ToList(),
        };
    }

    /// <summary>
    /// Rows → (label, value): the label joins the text columns, the value is the first number
    /// (so <c>top</c>'s count is used, not its percent).
    /// </summary>
    public static List<PanelItem> Items(QueryResult r)
    {
        ArgumentNullException.ThrowIfNull(r);
        if (r.Rows.Count == 0)
        {
            return [];
        }
        var numeric = Enumerable.Range(0, r.Columns.Count).Where(i => r.Rows.Any(row => IsNumber(row[i]))).ToList();
        if (numeric.Count == 0)
        {
            return [];
        }
        var valueColumn = numeric[0];
        var labelColumns = Enumerable.Range(0, r.Columns.Count).Where(i => !numeric.Contains(i)).ToList();
        return r.Rows
            .Select(row => new PanelItem(
                labelColumns.Count == 0 ? r.Columns[valueColumn] : string.Join(" / ", labelColumns.Select(i => Text(row[i]) is { Length: > 0 } t ? t : "(empty)")),
                Number(row[valueColumn]) ?? 0))
            .ToList();
    }

    public static object Bars(List<PanelItem> items) =>
        new { kind = "hbar", items = items.Take(BarItems).Select(i => new { name = i.Name, value = i.Value }).ToList() };

    public static object Pie(List<PanelItem> items)
    {
        var ordered = items.OrderByDescending(i => i.Value).ToList();
        var slices = ordered.Take(PieSlices).Select(i => new { name = i.Name, value = i.Value }).ToList();
        var rest = ordered.Skip(PieSlices).Sum(i => i.Value);
        if (rest > 0)
        {
            slices.Add(new { name = "Other", value = rest });
        }
        return new { kind = "pie", items = slices };
    }

    /// <summary>Country codes (2 letters, any case) → values; other labels are ignored.</summary>
    public static object Map(List<PanelItem> items)
    {
        var countries = items
            .Where(i => i.Name.Length == 2 && i.Name.All(char.IsAsciiLetter))
            .GroupBy(i => i.Name.ToUpperInvariant())
            .Select(g => new { name = g.Key, value = g.Sum(x => x.Value) })
            .ToList();
        return new { kind = "map", items = countries, max = countries.Count == 0 ? 0 : countries.Max(c => c.value) };
    }

    /// <summary>First number in the first row (a <c>stats</c> result), or null when there is none.</summary>
    public static double? Stat(QueryResult r)
    {
        ArgumentNullException.ThrowIfNull(r);
        if (r.Rows.Count == 0)
        {
            return null;
        }
        foreach (var value in r.Rows[0])
        {
            if (IsNumber(value))
            {
                return Number(value);
            }
        }
        return null;
    }

    public static (IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<string>> Rows, IReadOnlySet<int> NumericColumns) Table(QueryResult r)
    {
        ArgumentNullException.ThrowIfNull(r);
        var numeric = Enumerable.Range(0, r.Columns.Count).Where(i => r.Rows.Count > 0 && r.Rows.All(row => row[i] is null || IsNumber(row[i]))).ToHashSet();
        return (r.Columns, r.Rows.Take(TableRows).Select(row => (IReadOnlyList<string>)row.Select(Text).ToList()).ToList(), numeric);
    }

    /// <summary>
    /// For a single-number search ending in <c>| stats agg(…)</c> (no <c>by</c>), the same search as
    /// <c>| timechart agg(…)</c>, for the stat's sparkline. Null when it can't be derived.
    /// </summary>
    public static string? SparklineQuery(string query, IQueryParser parser)
    {
        ArgumentNullException.ThrowIfNull(parser);
        if (string.IsNullOrWhiteSpace(query))
        {
            return null;
        }
        PipelineNode pipeline;
        try
        {
            pipeline = parser.Parse(query);
        }
        catch (QueryParseException)
        {
            return null;
        }
        if (pipeline.Commands.Count == 0 || pipeline.Commands[^1] is not StatsCommand { By.Count: 0 } stats)
        {
            return null;
        }
        var at = stats.Position;
        if (at < 0 || at + 5 > query.Length || !query.AsSpan(at, 5).Equals("stats", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        var candidate = $"{query[..at]}timechart{query[(at + 5)..]}";
        try
        {
            parser.Parse(candidate);
            return candidate;
        }
        catch (QueryParseException)
        {
            return null;
        }
    }

    /// <summary>Sparkline points [ms, value] from a single-series timechart.</summary>
    public static object Sparkline(QueryResult r)
    {
        ArgumentNullException.ThrowIfNull(r);
        var points = r.Rows
            .Where(row => row[0] is DateTime && row.Length > 1)
            .Select(row => new double?[] { new DateTimeOffset(DateTime.SpecifyKind((DateTime)row[0]!, DateTimeKind.Utc)).ToUnixTimeMilliseconds(), Number(row[1]) })
            .ToList();
        return new { kind = "spark", points };
    }

    /// <summary>Display text for a value in the panel's unit.</summary>
    public static string Format(double? value, PanelUnit unit)
    {
        if (value is not { } v || double.IsNaN(v))
        {
            return "—";
        }
        return unit switch
        {
            PanelUnit.Duration => v >= 1e9 ? $"{v / 1e9:0.##} s" : v >= 1e6 ? $"{v / 1e6:0.#} ms" : $"{v / 1e3:0.#} µs",
            PanelUnit.Bytes => v >= 1L << 30 ? $"{v / (1L << 30):0.#} GB" : v >= 1 << 20 ? $"{v / (1 << 20):0.#} MB" : v >= 1 << 10 ? $"{v / (1 << 10):0.#} KB" : $"{v:0} B",
            PanelUnit.Percent => $"{v:0.#}%",
            _ => Math.Abs(v) >= 1e6 ? $"{v / 1e6:0.##}M" : Math.Abs(v) >= 1e4 ? $"{v / 1e3:0.#}k" : v == Math.Floor(v) ? v.ToString("N0", CultureInfo.InvariantCulture) : v.ToString("0.##", CultureInfo.InvariantCulture),
        };
    }

    /// <summary>"+12%" / "−40%" / "new" against the previous period; null when there's nothing to compare.</summary>
    public static string? Change(double? value, double? previous)
    {
        if (value is not { } v || previous is not { } p)
        {
            return null;
        }
        if (p == 0)
        {
            return v == 0 ? "no change" : "new";
        }
        var pct = (v - p) / Math.Abs(p) * 100;
        if (pct >= 1000)
        {
            // "+195500%" says nothing; "1956× previous" does.
            return string.Create(CultureInfo.InvariantCulture, $"{v / p:0}×");
        }
        return Math.Abs(pct) < 0.5 ? "no change" : $"{(pct > 0 ? "+" : "−")}{Math.Abs(pct):0}%";
    }

    private static bool IsNumber(object? value) => value is double or float or long or ulong or int or uint or short or ushort or byte or sbyte or decimal;

    private static double? Number(object? value) => value switch
    {
        null => null,
        double d => double.IsNaN(d) ? null : d,
        IConvertible c when IsNumber(value) => c.ToDouble(CultureInfo.InvariantCulture),
        string s when double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) => parsed,
        _ => null,
    };

    private static string Text(object? value) => DreaminGeek.Siem.Web.Search.SearchService.Format(value);
}
