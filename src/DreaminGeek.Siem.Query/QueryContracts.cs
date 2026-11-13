namespace DreaminGeek.Siem.Query;

/// <summary>A search request from the UI, an API client or a scheduled alert.</summary>
/// <param name="Query">Pipe-language text.</param>
/// <param name="From">Inclusive start of the time range (UTC).</param>
/// <param name="To">Exclusive end of the time range (UTC).</param>
/// <param name="TenantIds">
/// Tenant slugs the caller may see. Resolved from the user's memberships by the server, never from
/// user input. The compiler scopes every query to these; ClickHouse row policies are the second
/// line of defense.
/// </param>
public sealed record QueryRequest(string Query, DateTimeOffset From, DateTimeOffset To, IReadOnlyList<string> TenantIds);

public enum ResultShape
{
    /// <summary>Raw events (no aggregation): newest first, with <c>event.id</c> for drill-down.</summary>
    Events,
    /// <summary>A table from stats/top/table.</summary>
    Table,
    /// <summary>Time buckets from timechart: <c>_time</c>, optional series field, values.</summary>
    Timechart,
}

/// <summary>Parameterized SQL ready for ClickHouse. User values never appear in <see cref="Sql"/>.</summary>
/// <param name="Sql">SQL using <c>{name:Type}</c> placeholders.</param>
/// <param name="Parameters">Placeholder values.</param>
/// <param name="Shape">How the UI should render the result.</param>
/// <param name="Columns">Output column names, in order.</param>
/// <param name="RowLimit">The LIMIT applied; if the result has this many rows it may be truncated.</param>
/// <param name="ParameterTypes">ClickHouse type of each placeholder, e.g. <c>Array(String)</c>.</param>
public sealed record CompiledQuery(
    string Sql, IReadOnlyDictionary<string, object> Parameters, ResultShape Shape, IReadOnlyList<string> Columns, int RowLimit,
    IReadOnlyDictionary<string, string> ParameterTypes)
{
    /// <summary>Tenants this query is scoped to; the executor also activates their ClickHouse row-policy roles.</summary>
    public IReadOnlyList<string> TenantIds { get; init; } = [];
}

/// <summary>Rows returned by a search.</summary>
/// <param name="Columns">Column names, in order.</param>
/// <param name="Rows">Row values aligned with <paramref name="Columns"/> (null for SQL NULL).</param>
/// <param name="Truncated">True when the row limit was hit and more rows may exist.</param>
/// <param name="Elapsed">Server round-trip time.</param>
public sealed record QueryResult(IReadOnlyList<string> Columns, IReadOnlyList<object?[]> Rows, ResultShape Shape, bool Truncated, TimeSpan Elapsed)
{
    /// <summary>Index of a column by name, or -1.</summary>
    public int ColumnIndex(string name)
    {
        for (var i = 0; i < Columns.Count; i++)
        {
            if (string.Equals(Columns[i], name, StringComparison.Ordinal))
            {
                return i;
            }
        }
        return -1;
    }
}

public interface IQueryExecutor
{
    Task<QueryResult> ExecuteAsync(CompiledQuery query, CancellationToken cancellationToken);
}

public sealed class CompilerOptions
{
    /// <summary>Events returned when the query has no head/limit.</summary>
    public int DefaultEventLimit { get; set; } = 1000;

    /// <summary>Hard cap on rows returned by any query.</summary>
    public int MaxRows { get; set; } = 10_000;

    /// <summary>Target number of buckets when timechart has no span.</summary>
    public int TimechartBuckets { get; set; } = 120;
}

public interface IQueryParser
{
    PipelineNode Parse(string query);
}

public interface IQueryCompiler
{
    CompiledQuery Compile(PipelineNode pipeline, QueryRequest request);

    /// <summary>Extra field names present in the caller's events, most common first (for autocomplete).</summary>
    CompiledQuery CompileFieldNames(QueryRequest request, int limit = 500);
}

/// <summary>A query error the user should see, with the character position it refers to.</summary>
public sealed class QueryParseException(string message, int position) : Exception(message)
{
    public int Position { get; } = position;
}
