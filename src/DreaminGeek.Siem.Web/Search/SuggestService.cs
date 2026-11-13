using System.Globalization;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Security;
using Microsoft.Extensions.Caching.Memory;

namespace DreaminGeek.Siem.Web.Search;

public sealed record Suggestion(string Label, string Insert, string? Detail, string Kind);

public sealed record SuggestResponse(int ReplaceStart, int ReplaceEnd, string Hint, IReadOnlyList<Suggestion> Items);

/// <summary>
/// Autocomplete for the search box. Field names and values come from the caller's own tenants
/// (via the same scoped, row-policy-protected queries as searches) and are cached for 5 minutes.
/// </summary>
public sealed partial class SuggestService(
    IQueryCompiler compiler, IQueryExecutor executor, SearchService search, IMemoryCache cache, ILogger<SuggestService> logger)
{
    private const int MaxItems = 25;
    private static readonly TimeSpan CacheTime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan Lookback = TimeSpan.FromHours(24);
    private static readonly string[] SearchKeywords = ["AND", "OR", "NOT"];
    private static readonly string[] ExpressionKeywords = ["AND", "OR", "NOT", "IN"];

    public async Task<SuggestResponse> SuggestAsync(UserAccess access, string query, int cursor, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(access);
        var context = QueryAssist.Analyze(query, cursor);
        var prefix = context.Prefix;
        IEnumerable<Suggestion> items = context.Kind switch
        {
            AssistKind.Command => QueryAssist.Commands
                .Select(c => new Suggestion(c.Name, c.Name + " ", c.Description, "command")),
            AssistKind.Field => (await FieldsAsync(access, ct))
                .Select(f => new Suggestion(f.Name, context.InSearchClause ? f.Name + "=" : f.Name, f.Detail, "field"))
                .Concat(context.InSearchClause ? Keywords(SearchKeywords) : []),
            AssistKind.Aggregation => QueryAssist.Aggregations
                .Select(a => new Suggestion(a.Name, a.Insert, a.Detail, "aggregation"))
                .Append(new Suggestion("by", "by ", "Split the results by fields", "keyword"))
                .Concat(context.Command == "timechart" && !query.Contains("span=", StringComparison.OrdinalIgnoreCase)
                    ? [new Suggestion("span=", "span=", "Bucket size, e.g. span=15m", "keyword")] : []),
            AssistKind.Expression => (await FieldsAsync(access, ct))
                .Select(f => new Suggestion(f.Name, f.Name, f.Detail, "field"))
                .Concat(QueryAssist.Functions.Select(fn => new Suggestion(fn.Name, fn.Insert, fn.Detail, "function")))
                .Concat(Keywords(ExpressionKeywords)),
            AssistKind.Value when context.Field is { } field => (await ValuesAsync(access, field, ct))
                .Select(v => new Suggestion(v.Value, Quote(v.Value, context.QuoteValues) + " ", $"{v.Count.ToString("N0", CultureInfo.InvariantCulture)} in 24h", "value")),
            _ => [],
        };

        var ranked = Rank(items, prefix).Take(MaxItems).ToList();
        return new SuggestResponse(context.ReplaceStart, context.ReplaceEnd, context.Hint, ranked);
    }

    /// <summary>Starts-with matches first, then contains; otherwise keeps the source order (frequency).</summary>
    private static IEnumerable<Suggestion> Rank(IEnumerable<Suggestion> items, string prefix)
    {
        var list = items.DistinctBy(i => (i.Label, i.Kind)).ToList();
        if (prefix.Length == 0)
        {
            return list;
        }
        return list
            .Select((item, index) => (item, index, starts: item.Label.StartsWith(prefix, StringComparison.OrdinalIgnoreCase),
                contains: item.Label.Contains(prefix, StringComparison.OrdinalIgnoreCase)))
            .Where(x => x.contains && !string.Equals(x.item.Label, prefix, StringComparison.Ordinal))
            .OrderByDescending(x => x.starts)
            .ThenBy(x => x.index)
            .Select(x => x.item);
    }

    private static IEnumerable<Suggestion> Keywords(IEnumerable<string> words) =>
        words.Select(w => new Suggestion(w, w + " ", "operator", "keyword"));

    private async Task<IReadOnlyList<(string Name, string Detail)>> FieldsAsync(UserAccess access, CancellationToken ct)
    {
        var key = "assist:fields:" + string.Join(',', access.Tenants);
        if (cache.TryGetValue(key, out IReadOnlyList<(string, string)>? cached) && cached is not null)
        {
            return cached;
        }

        var fields = QueryAssist.BuiltInFields.ToList();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var compiled = compiler.CompileFieldNames(new QueryRequest("", now - Lookback, now, access.Tenants));
            var result = await executor.ExecuteAsync(compiled, ct);
            var known = fields.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
            fields.InsertRange(0, result.Rows
                .Select(r => (Name: (string)r[0]!, Count: Convert.ToInt64(r[1], CultureInfo.InvariantCulture)))
                .Where(r => !known.Contains(r.Name))
                .Select(r => (r.Name, $"seen in {r.Count.ToString("N0", CultureInfo.InvariantCulture)} events")));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogLookupFailed(logger, ex, "field names");
        }

        // Most useful first: the common ECS fields, then discovered fields by frequency, then shortcuts.
        var ordered = fields
            .OrderBy(f => f.Detail == "built-in field" ? 0 : f.Detail.StartsWith("seen in", StringComparison.Ordinal) ? 1 : 2)
            .ToList();
        cache.Set(key, (IReadOnlyList<(string, string)>)ordered, CacheTime);
        return ordered;
    }

    private async Task<IReadOnlyList<(string Value, long Count)>> ValuesAsync(UserAccess access, string field, CancellationToken ct)
    {
        var key = $"assist:values:{string.Join(',', access.Tenants)}:{field}";
        if (cache.TryGetValue(key, out IReadOnlyList<(string, long)>? cached) && cached is not null)
        {
            return cached;
        }

        var now = DateTimeOffset.UtcNow;
        var response = await search.RunAsync($"* | top limit=200 {field}", now - Lookback, now, access.Tenants, ct);
        IReadOnlyList<(string, long)> values = response.Result is { } result
            ? result.Rows
                .Select(r => (Value: SearchService.Format(r[0]), Count: Convert.ToInt64(r[1], CultureInfo.InvariantCulture)))
                .Where(v => v.Value.Length > 0 && v.Value != "0")
                .ToList()
            : [];
        cache.Set(key, values, CacheTime);
        return values;
    }

    /// <summary>Bare values when safe in the search clause; otherwise a quoted string.</summary>
    private static string Quote(string value, bool always) =>
        !always && value.Length > 0 && value.All(c => !char.IsWhiteSpace(c) && c is not ('"' or '\'' or '|' or '(' or ')' or ',' or '=' or '<' or '>' or '!'))
            ? value
            : SearchService.Quote(value);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Autocomplete lookup of {What} failed")]
    private static partial void LogLookupFailed(ILogger logger, Exception ex, string what);
}
