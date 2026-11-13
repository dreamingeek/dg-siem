namespace DreaminGeek.Siem.Query;

// AST for the DG SIEM pipe language, e.g.
//   event.dataset=unifi.firewall event.action=drop | stats count() as hits by source.ip | sort -hits | head 10
// The parser (PipeParser) produces these; the compiler (ClickHouseCompiler) turns them into
// parameterized ClickHouse SQL.

/// <summary>A full query: an initial search followed by zero or more piped commands.</summary>
public sealed record PipelineNode(SearchNode Search, IReadOnlyList<CommandNode> Commands);

/// <summary>Leading search clause: terms and field comparisons, implicitly ANDed. Null filter = everything.</summary>
public sealed record SearchNode(Expr? Filter);

public abstract record CommandNode(int Position);
public sealed record WhereCommand(int Position, Expr Condition) : CommandNode(Position);
public sealed record EvalCommand(int Position, IReadOnlyList<(string Field, Expr Value)> Assignments) : CommandNode(Position);
public sealed record RexCommand(int Position, string SourceField, string Pattern) : CommandNode(Position);
public sealed record StatsCommand(int Position, IReadOnlyList<Aggregation> Aggregations, IReadOnlyList<string> By) : CommandNode(Position);
public sealed record TimechartCommand(int Position, TimeSpan? Span, IReadOnlyList<Aggregation> Aggregations, string? By) : CommandNode(Position);
public sealed record SortCommand(int Position, IReadOnlyList<SortKey> Keys) : CommandNode(Position);
public sealed record HeadCommand(int Position, int Count) : CommandNode(Position);
public sealed record DedupCommand(int Position, IReadOnlyList<string> Fields) : CommandNode(Position);
public sealed record TableCommand(int Position, IReadOnlyList<string> Fields) : CommandNode(Position);
public sealed record FieldsCommand(int Position, IReadOnlyList<string> Fields, bool Exclude) : CommandNode(Position);
/// <summary><c>fieldsummary [maxvals=N] [fields]</c>: the most common values of several fields at once.</summary>
public sealed record FieldSummaryCommand(int Position, IReadOnlyList<string> Fields, int MaxValues) : CommandNode(Position);
/// <summary><c>top field [by field] [limit=N]</c>: most common values with count and percent.</summary>
public sealed record TopCommand(int Position, string Field, string? By, int Limit) : CommandNode(Position);

/// <summary>An aggregation like <c>count()</c>, <c>dc(user.name)</c>, <c>p95(network.bytes)</c>.</summary>
public sealed record Aggregation(string Function, string? Field, string? Alias)
{
    /// <summary>Output column name: the alias, or Splunk-style <c>dc(user.name)</c> / <c>count</c>.</summary>
    public string OutputName => Alias ?? (Field is null ? Function : $"{Function}({Field})");
}

public sealed record SortKey(string Field, bool Descending);

public abstract record Expr(int Position);
/// <summary>Search term matched against the message (case-insensitive). In unquoted terms <c>*</c> is a wildcard.</summary>
public sealed record TermExpr(int Position, string Text, bool Quoted) : Expr(Position);
public sealed record FieldRef(int Position, string Name) : Expr(Position);
/// <summary>A string or number literal.</summary>
public sealed record Literal(int Position, object Value) : Expr(Position);
/// <summary>= != &lt; &lt;= &gt; &gt;= AND OR + - * / % and "." (string concatenation).</summary>
public sealed record BinaryExpr(int Position, string Op, Expr Left, Expr Right) : Expr(Position);
public sealed record NotExpr(int Position, Expr Operand) : Expr(Position);
public sealed record NegateExpr(int Position, Expr Operand) : Expr(Position);
public sealed record InExpr(int Position, Expr Value, IReadOnlyList<Expr> Options) : Expr(Position);
public sealed record CallExpr(int Position, string Function, IReadOnlyList<Expr> Args) : Expr(Position);
