using System.Globalization;
using DreaminGeek.Siem.Query;

namespace DreaminGeek.Siem.Web.Search;

public sealed record SearchResponse(QueryResult? Result, string? Error, int? ErrorPosition, string? Sql);

/// <summary>Top values of one field over the current search.</summary>
public sealed record FieldValues(string Field, IReadOnlyList<(string Value, long Count)> Values);

/// <summary>An event's full record: every promoted field, the raw line and the extra-fields map.</summary>
public sealed record EventDetail(Guid Id, string Tenant, DateTime Timestamp, string HostName, IReadOnlyList<(string Field, string Value)> Fields, string Raw);

/// <summary>Parse → compile (tenant-scoped) → execute.</summary>
public sealed partial class SearchService(
    IQueryParser parser, IQueryCompiler compiler, IQueryExecutor executor, ILogger<SearchService> logger)
{
    /// <param name="tenants">From <see cref="Security.TenantAccess"/> only, never from the client.</param>
    public async Task<SearchResponse> RunAsync(string query, DateTimeOffset from, DateTimeOffset to, IReadOnlyList<string> tenants, CancellationToken ct)
    {
        CompiledQuery compiled;
        try
        {
            compiled = compiler.Compile(parser.Parse(query ?? string.Empty), new QueryRequest(query ?? string.Empty, from, to, tenants));
        }
        catch (QueryParseException ex)
        {
            return new SearchResponse(null, ex.Message, ex.Position, null);
        }

        try
        {
            return new SearchResponse(await executor.ExecuteAsync(compiled, ct), null, null, compiled.Sql);
        }
        catch (DreaminGeek.Siem.Storage.ClickHouse.SearchUnavailableException ex)
        {
            return new SearchResponse(null, ex.Message, null, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // ClickHouse errors (bad regex, type mismatch, timeout) are user-facing; keep the first line.
            LogQueryFailed(logger, ex, compiled.Sql);
            var message = ex.Message.Split('\n')[0];
            return new SearchResponse(null, $"Query failed: {message}", null, compiled.Sql);
        }
    }

    /// <summary>Top values of the sidebar fields, for searches that return raw events.</summary>
    public async Task<IReadOnlyList<FieldValues>> SummarizeAsync(string query, DateTimeOffset from, DateTimeOffset to, IReadOnlyList<string> tenants, CancellationToken ct)
    {
        var response = await RunAsync((query ?? string.Empty).TrimEnd() + " | fieldsummary maxvals=8", from, to, tenants, ct);
        if (response.Result is not { } result)
        {
            return [];
        }
        return result.Rows
            .GroupBy(r => (string)r[0]!)
            .Select(g => new FieldValues(g.Key, g.Select(r => ((string)r[1]!, Convert.ToInt64(r[2], CultureInfo.InvariantCulture))).ToList()))
            .ToList();
    }

    private static readonly string[] DetailFields =
    [
        "@timestamp", "tenant", "event.id", "host.name", "observer.ip", "event.dataset", "event.module", "event.action",
        "event.outcome", "log.level", "source.ip", "source.port", "destination.ip", "destination.port",
        "network.transport", "network.protocol", "user.name", "message", "event.ingested", "raw", "_fields",
    ];

    /// <summary>One event by id. The caller passes the row's tenant and timestamp to keep the lookup cheap and scoped.</summary>
    public async Task<EventDetail?> GetEventAsync(Guid id, string tenant, DateTime timestamp, IReadOnlyList<string> allowedTenants, CancellationToken ct)
    {
        if (!allowedTenants.Contains(tenant))
        {
            return null;
        }
        var at = new DateTimeOffset(DateTime.SpecifyKind(timestamp, DateTimeKind.Utc));
        var response = await RunAsync($"event.id={Quote(id.ToString())} | table {string.Join(", ", DetailFields)}",
            at.AddSeconds(-2), at.AddSeconds(2), [tenant], ct);
        if (response.Result is not { Rows.Count: > 0 } result)
        {
            return null;
        }

        var row = result.Rows[0];
        var fields = new List<(string, string)>();
        for (var i = 0; i < result.Columns.Count; i++)
        {
            var name = result.Columns[i];
            if (name is "raw" or "_fields" or "event.id" or "tenant" or "@timestamp")
            {
                continue;
            }
            var value = Format(row[i]);
            if (value.Length > 0 && value != "0")
            {
                fields.Add((name, value));
            }
        }
        if (row[result.ColumnIndex("_fields")] is System.Collections.IDictionary map)
        {
            foreach (System.Collections.DictionaryEntry entry in map)
            {
                fields.Add((entry.Key.ToString()!, entry.Value?.ToString() ?? string.Empty));
            }
        }
        fields.Sort((a, b) => string.CompareOrdinal(a.Item1, b.Item1));
        return new EventDetail(id, tenant, timestamp, Format(row[result.ColumnIndex("host.name")]), fields, Format(row[result.ColumnIndex("raw")]));
    }

    /// <summary>The events just before and after one event from the same host and tenant, oldest first.</summary>
    public async Task<(QueryResult? Before, QueryResult? After)> SurroundingAsync(
        string tenant, string hostName, DateTime timestamp, int count, IReadOnlyList<string> allowedTenants, CancellationToken ct)
    {
        if (!allowedTenants.Contains(tenant))
        {
            return (null, null);
        }
        var at = new DateTimeOffset(DateTime.SpecifyKind(timestamp, DateTimeKind.Utc));
        var filter = hostName.Length > 0 ? $"host.name={Quote(hostName)}" : "*";
        // "Before" includes the event itself (newest first, so reverse it); "after" starts just past it.
        var before = await RunAsync($"{filter} | head {count + 1}", at.AddHours(-6), at.AddMilliseconds(1), [tenant], ct);
        var after = await RunAsync($"{filter} | sort +@timestamp | head {count}", at.AddMilliseconds(1), at.AddHours(6), [tenant], ct);
        return (before.Result, after.Result);
    }

    /// <summary>A double-quoted query string value.</summary>
    public static string Quote(string value) =>
        "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    /// <summary>Adds <c>field="value"</c> (or <c>NOT field="value"</c>) to the search clause, before the first pipe.</summary>
    public static string AddFilter(string query, string field, string value, bool exclude)
    {
        var clause = (exclude ? "NOT " : string.Empty) + field + "=" + Quote(value);
        var segments = Lexer.SplitPipes(query ?? string.Empty);
        var search = segments[0].Text.Trim();
        var rest = query is null ? string.Empty : query[segments[0].Text.Length..];
        search = search is "" or "*" ? clause : search + " " + clause;
        return rest.Length > 0 ? search + " " + rest.TrimStart() : search;
    }

    public static string Format(object? value) => value switch
    {
        null => string.Empty,
        DateTime dt => dt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
        DateTimeOffset dto => dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
        double d => d.ToString("0.##", CultureInfo.InvariantCulture),
        float f => f.ToString("0.##", CultureInfo.InvariantCulture),
        string s => s,
        System.Collections.IDictionary map => string.Join(", ", map.Keys.Cast<object>().Select(k => $"{k}={map[k]}")),
        System.Collections.IEnumerable list => string.Join(", ", list.Cast<object?>().Select(Format)),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty,
    };

    /// <summary>"-15m", "-24h", "-7d" relative to now, "now", or an ISO-8601 timestamp.</summary>
    public static DateTimeOffset ParseTime(string? value, DateTimeOffset now, DateTimeOffset fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }
        if (value.Equals("now", StringComparison.OrdinalIgnoreCase))
        {
            return now;
        }
        if (value.StartsWith('-'))
        {
            return now - PipeParser.ParseSpan(new Token(TokenKind.Word, value[1..], 0));
        }
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Search failed. SQL: {Sql}")]
    private static partial void LogQueryFailed(ILogger logger, Exception ex, string sql);
}
