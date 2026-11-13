using System.Globalization;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Query;

namespace DreaminGeek.Siem.Alerting;

/// <summary>The rule's query or settings are unusable; the message is shown to the admin as-is.</summary>
public sealed class AlertRuleException(string message) : Exception(message);

/// <summary>One alert to send: the whole result (trigger once) or one result row (trigger per result).</summary>
/// <param name="Key">What makes a repeat "the same alert" (empty for trigger-once).</param>
/// <param name="Label">Human-readable key, e.g. <c>src=10.0.0.5</c>.</param>
public sealed record AlertGroup(string Key, string Label, IReadOnlyList<object?[]> Rows);

/// <param name="Count">Matching events (event searches) or result rows (stats/top/table).</param>
/// <param name="CountsEvents">True when <paramref name="Count"/> is events, false when it is result rows.</param>
public sealed record AlertEvaluation(
    long Count, bool CountsEvents, bool ConditionMet, IReadOnlyList<string> Columns, IReadOnlyList<object?[]> Sample, IReadOnlyList<AlertGroup> Groups);

/// <summary>Runs an alert rule's query for one tenant and decides what fires.</summary>
public sealed class AlertEvaluator(IQueryParser parser, IQueryCompiler compiler, IQueryExecutor executor)
{
    /// <summary>Rows kept for notifications and history.</summary>
    public const int SampleRows = 20;

    /// <summary>Most alerts one per-result rule can raise in one run (per tenant).</summary>
    public const int MaxGroups = 50;

    /// <summary>The window ending now: <c>-15m</c> → the last 15 minutes.</summary>
    public static (DateTimeOffset From, DateTimeOffset To) Window(string timeRange, DateTimeOffset now) =>
        (now - ParseLookback(timeRange), now);

    public static TimeSpan ParseLookback(string timeRange)
    {
        var text = (timeRange ?? string.Empty).Trim().TrimStart('-');
        try
        {
            var span = PipeParser.ParseSpan(new Token(TokenKind.Word, text, 0));
            return span > TimeSpan.Zero && span <= TimeSpan.FromDays(31)
                ? span
                : throw new AlertRuleException("The time range must be between 1 minute and 31 days.");
        }
        catch (QueryParseException)
        {
            throw new AlertRuleException($"\"{timeRange}\" isn't a time range. Use e.g. 15m, 1h or 1d.");
        }
    }

    /// <summary>Parses the query (throws <see cref="AlertRuleException"/> with the parser's message).</summary>
    public PipelineNode Validate(string query)
    {
        try
        {
            return parser.Parse(query);
        }
        catch (QueryParseException ex)
        {
            throw new AlertRuleException(ex.Message);
        }
    }

    public async Task<AlertEvaluation> EvaluateAsync(AlertRule rule, string tenant, DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var request = new QueryRequest(rule.Query, from, to, [tenant]);
        var compiled = compiler.Compile(Validate(rule.Query), request);

        if (compiled.Shape != ResultShape.Events)
        {
            var table = await executor.ExecuteAsync(compiled, ct);
            var met = ConditionMet(rule.Condition, rule.Threshold, table.Rows.Count);
            return new AlertEvaluation(table.Rows.Count, false, met, table.Columns, table.Rows.Take(SampleRows).ToList(),
                Groups(rule, table.Columns, table.Rows, met));
        }

        // Event searches: count every match (not just the first page), then fetch a few for the message.
        var countQuery = compiler.Compile(Validate(rule.Query + "\n| stats count() as matched"), request);
        var counted = await executor.ExecuteAsync(countQuery, ct);
        var count = counted.Rows.Count > 0 ? Convert.ToInt64(counted.Rows[0][0], CultureInfo.InvariantCulture) : 0;
        var conditionMet = ConditionMet(rule.Condition, rule.Threshold, count);
        if (!conditionMet || count == 0)
        {
            return new AlertEvaluation(count, true, conditionMet, [], [], Groups(rule, [], [], conditionMet));
        }

        var limit = rule.Trigger == AlertTrigger.PerResult ? MaxGroups : SampleRows;
        var sample = await executor.ExecuteAsync(compiler.Compile(Validate($"{rule.Query}\n| head {limit}"), request), ct);
        return new AlertEvaluation(count, true, conditionMet, sample.Columns, sample.Rows.Take(SampleRows).ToList(),
            Groups(rule, sample.Columns, sample.Rows, conditionMet));
    }

    public static bool ConditionMet(AlertCondition condition, long threshold, long count) => condition switch
    {
        AlertCondition.CountGreaterThan => count > threshold,
        AlertCondition.CountLessThan => count < threshold,
        _ => count > 0,
    };

    /// <summary>Splits a result into the alerts it raises.</summary>
    public static IReadOnlyList<AlertGroup> Groups(AlertRule rule, IReadOnlyList<string> columns, IReadOnlyList<object?[]> rows, bool conditionMet)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(rows);
        if (!conditionMet)
        {
            return [];
        }
        // "Fewer than N" is about the whole result (often zero rows), so it is always one alert.
        if (rule.Trigger == AlertTrigger.Once || rule.Condition == AlertCondition.CountLessThan || rows.Count == 0)
        {
            return [new AlertGroup(string.Empty, string.Empty, rows.Take(SampleRows).ToList())];
        }

        var keyColumns = KeyColumns(rule.SuppressBy, columns, rows);
        return rows
            // A row with no key (e.g. events without a source address in "stats count() by src") identifies nothing.
            .Where(row => keyColumns.Any(i => AlertEvaluator.Text(row[i]).Length > 0))
            .Take(MaxGroups)
            .Select(row =>
            {
                var label = string.Join(", ", keyColumns.Select(i => $"{columns[i]}={Text(row[i])}"));
                return new AlertGroup(label, label, [row]);
            })
            .GroupBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new AlertGroup(g.Key, g.First().Label, g.SelectMany(x => x.Rows).ToList()))
            .ToList();
    }

    /// <summary>
    /// Columns that identify a result row: the "suppress by" fields when given (shortcuts allowed), otherwise
    /// the text columns, so <c>stats count() by src</c> keys on <c>src</c> and not on the changing count.
    /// </summary>
    internal static IReadOnlyList<int> KeyColumns(string? suppressBy, IReadOnlyList<string> columns, IReadOnlyList<object?[]> rows)
    {
        var named = (suppressBy ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(name => IndexOf(columns, name))
            .Where(i => i >= 0)
            .Distinct()
            .ToList();
        if (named.Count > 0)
        {
            return named;
        }

        var text = Enumerable.Range(0, columns.Count)
            .Where(i => rows.Count > 0 && rows[0][i] is not (null or sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal))
            .ToList();
        return text.Count > 0 ? text : Enumerable.Range(0, columns.Count).ToList();
    }

    private static int IndexOf(IReadOnlyList<string> columns, string name)
    {
        for (var i = 0; i < columns.Count; i++)
        {
            if (string.Equals(columns[i], name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(columns[i], QueryAssist.CanonicalField(name), StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }
        return -1;
    }

    /// <summary>Display text for a result value (dates as UTC, lists comma-joined).</summary>
    public static string Text(object? value) => value switch
    {
        null => string.Empty,
        DateTime dt => dt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        DateTimeOffset dto => dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        double d => d.ToString("0.##", CultureInfo.InvariantCulture),
        float f => f.ToString("0.##", CultureInfo.InvariantCulture),
        string s => s,
        System.Collections.IDictionary map => string.Join(", ", map.Keys.Cast<object>().Select(k => $"{k}={map[k]}")),
        System.Collections.IEnumerable list => string.Join(", ", list.Cast<object?>().Select(Text)),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty,
    };
}
