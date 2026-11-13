namespace DreaminGeek.Siem.Query;

/// <summary>What kind of token belongs at the cursor.</summary>
public enum AssistKind
{
    /// <summary>Nothing useful to suggest (a new eval name, inside a regex, ...).</summary>
    None,
    /// <summary>A command name, right after a pipe.</summary>
    Command,
    /// <summary>A field name.</summary>
    Field,
    /// <summary>A value of <see cref="AssistContext.Field"/>.</summary>
    Value,
    /// <summary>An aggregation in stats/timechart (count, dc, avg, ...), or the "by" keyword.</summary>
    Aggregation,
    /// <summary>An expression in where/eval: fields, functions and operators.</summary>
    Expression,
}

/// <summary>Where the cursor is and what may go there.</summary>
/// <param name="Kind">What to suggest.</param>
/// <param name="Prefix">What the user has typed of the current token (for filtering).</param>
/// <param name="ReplaceStart">Start of the text a chosen suggestion replaces.</param>
/// <param name="ReplaceEnd">End of the text a chosen suggestion replaces.</param>
/// <param name="Field">For <see cref="AssistKind.Value"/>: the field whose values to suggest.</param>
/// <param name="Command">The command the cursor is in, or null in the search clause.</param>
/// <param name="Hint">One-line syntax reminder for the current command.</param>
/// <param name="InSearchClause">True before the first pipe (field names insert as <c>field=</c>).</param>
/// <param name="QuoteValues">Values must be quoted here (where/eval), not just when they contain spaces.</param>
public sealed record AssistContext(
    AssistKind Kind, string Prefix, int ReplaceStart, int ReplaceEnd, string? Field, string? Command, string Hint,
    bool InSearchClause, bool QuoteValues);

public sealed record AssistItem(string Name, string Insert, string Detail);

/// <summary>
/// Works out, from the query text and cursor position, what the user is typing: the basis for
/// autocomplete. Tolerates incomplete queries (it never needs the query to parse).
/// </summary>
public static class QueryAssist
{
    public const string SearchHint = "Search: words, \"exact phrases\", field=value, field>n, NOT, OR, ( ). Then | a command.";

    public static readonly IReadOnlyList<(string Name, string Syntax, string Description)> Commands =
    [
        ("stats", "stats <agg>(field) [as name], … [by field, …]", "Count, sum or average events, optionally per field"),
        ("top", "top [limit=N] <field> [by field]", "Most common values with count and percent"),
        ("timechart", "timechart [span=15m] <agg>(field), … [by field]", "Counts over time, charted"),
        ("where", "where <condition>   e.g. where dport > 1024 AND NOT user IN (\"root\")", "Keep events matching a condition"),
        ("eval", "eval <name> = <expression>, …", "Calculate a new field"),
        ("rex", "rex [field=<field>] \"regex with (?<name>…) groups\"", "Extract fields with a regular expression"),
        ("table", "table field, …", "Show only these columns"),
        ("fields", "fields [-] field, …", "Keep (or with -, remove) columns"),
        ("sort", "sort [-]field, …   (- for descending)", "Order the results"),
        ("head", "head N", "Keep the first N results"),
        ("dedup", "dedup field, …", "Keep the first event for each value"),
        ("fieldsummary", "fieldsummary [maxvals=N] [field, …]", "Top values of several fields at once"),
    ];

    public static readonly IReadOnlyList<AssistItem> Aggregations =
    [
        new("count", "count()", "Number of events"),
        new("dc", "dc(", "Distinct count of a field"),
        new("sum", "sum(", "Total of a numeric field"),
        new("avg", "avg(", "Average of a numeric field"),
        new("min", "min(", "Smallest value"),
        new("max", "max(", "Largest value"),
        new("median", "median(", "Median value"),
        new("p95", "p95(", "95th percentile (also p50, p90, p99)"),
        new("values", "values(", "Distinct values, listed"),
        new("earliest", "earliest(", "Value from the oldest event"),
        new("latest", "latest(", "Value from the newest event"),
    ];

    public static readonly IReadOnlyList<AssistItem> Functions =
    [
        new("lower", "lower(", "lower(text)"),
        new("upper", "upper(", "upper(text)"),
        new("len", "len(", "len(text): length"),
        new("tonumber", "tonumber(", "tonumber(text)"),
        new("tostring", "tostring(", "tostring(value)"),
        new("round", "round(", "round(number, digits)"),
        new("abs", "abs(", "abs(number)"),
        new("substr", "substr(", "substr(text, start, length)"),
        new("replace", "replace(", "replace(text, \"regex\", \"with\")"),
        new("if", "if(", "if(condition, then, else)"),
        new("coalesce", "coalesce(", "coalesce(a, b, …): first non-empty"),
        new("isnull", "isnull(", "isnull(field): field is empty"),
        new("isnotnull", "isnotnull(", "isnotnull(field)"),
        new("like", "like(", "like(field, \"pattern%\")"),
        new("match", "match(", "match(field, \"regex\")"),
        new("cidrmatch", "cidrmatch(", "cidrmatch(\"10.0.0.0/8\", field)"),
        new("now", "now()", "Current time"),
        new("ago", "ago(", "ago(\"2h\"): that long before now"),
    ];

    /// <summary>Built-in ECS fields and shortcuts (name, description).</summary>
    public static IEnumerable<(string Name, string Detail)> BuiltInFields => FieldCatalog.Suggestable();

    /// <summary>The ECS name for a shortcut (<c>src</c> → <c>source.ip</c>); other names unchanged.</summary>
    public static string CanonicalField(string name) => FieldCatalog.Canonical(name);

    private static readonly Dictionary<string, string> Hints = Commands.ToDictionary(c => c.Name, c => c.Syntax, StringComparer.OrdinalIgnoreCase);

    public static AssistContext Analyze(string query, int cursor)
    {
        query ??= string.Empty;
        cursor = Math.Clamp(cursor, 0, query.Length);
        var before = query[..cursor];

        // Inside an open quote: a value being typed, e.g. user.name="Chr|
        if (OpenQuoteAt(before) is int quote)
        {
            var closing = query.IndexOf(query[quote], cursor);
            var end = closing >= 0 ? closing + 1 : cursor;
            var (segIndex, segStart) = Segment(before[..quote]);
            var command = segIndex == 0 ? null : FirstWord(before[segStart..quote]);
            var field = FieldBeforeOperator(before, quote);
            var kind = field is not null && command is null or "where" or "search" ? AssistKind.Value : AssistKind.None;
            return new AssistContext(kind, before[(quote + 1)..], quote, end, field, command, HintFor(command), segIndex == 0, true);
        }

        var (index, start) = Segment(before);
        var tokenStart = cursor;
        while (tokenStart > start && IsTokenChar(before[tokenStart - 1]))
        {
            tokenStart--;
        }
        var tokenEnd = cursor;
        while (tokenEnd < query.Length && IsTokenChar(query[tokenEnd]))
        {
            tokenEnd++;
        }
        var prefix = before[tokenStart..];
        var valueField = FieldBeforeOperator(before, tokenStart);

        if (index == 0)
        {
            return valueField is not null
                ? new AssistContext(AssistKind.Value, prefix, tokenStart, tokenEnd, valueField, null, SearchHint, true, false)
                : new AssistContext(AssistKind.Field, prefix, tokenStart, tokenEnd, null, null, SearchHint, true, false);
        }

        var segment = before[start..tokenStart];
        var name = FirstWord(segment);
        if (name is null)
        {
            // Still typing the command name.
            return new AssistContext(AssistKind.Command, prefix, tokenStart, tokenEnd, null, null, "Type a command: stats, top, timechart, where, eval, table, sort…", false, false);
        }

        var cmd = name.ToLowerInvariant();
        var hint = HintFor(cmd);
        var words = Words(segment);
        var last = words.Count > 0 ? words[^1] : string.Empty;
        AssistContext Make(AssistKind kind, string? field = null, bool quote = false, int? replaceStart = null, string? pfx = null) =>
            new(kind, pfx ?? prefix, replaceStart ?? tokenStart, tokenEnd, field, cmd, hint, false, quote);

        switch (cmd)
        {
            case "where" or "search":
                return valueField is not null ? Make(AssistKind.Value, valueField, quote: true) : Make(AssistKind.Expression);

            case "eval":
                // "eval x = <expression>": suggestions only on the right of an '='.
                return segment.Contains('=', StringComparison.Ordinal) && !segment.TrimEnd().EndsWith(',') ? Make(AssistKind.Expression) : Make(AssistKind.None);

            case "stats" or "timechart":
                if (Unclosed(segment, '(', ')') || words.Any(w => w.Equals("by", StringComparison.OrdinalIgnoreCase)))
                {
                    return Make(AssistKind.Field);
                }
                return last.Equals("as", StringComparison.OrdinalIgnoreCase) ? Make(AssistKind.None) : Make(AssistKind.Aggregation);

            case "top" or "dedup" or "table" or "fields" or "fieldsummary":
                if (prefix.StartsWith('-') || prefix.StartsWith('+'))
                {
                    return Make(AssistKind.Field, replaceStart: tokenStart + 1, pfx: prefix[1..]);
                }
                return valueField is not null ? Make(AssistKind.None) : Make(AssistKind.Field);

            case "sort":
                return prefix.StartsWith('-') || prefix.StartsWith('+')
                    ? Make(AssistKind.Field, replaceStart: tokenStart + 1, pfx: prefix[1..])
                    : Make(AssistKind.Field);

            case "rex":
                return valueField == "field" ? Make(AssistKind.Field) : Make(AssistKind.None);

            default:
                return Make(AssistKind.None);
        }
    }

    private static string HintFor(string? command) =>
        command is null ? SearchHint : Hints.GetValueOrDefault(command, "Unknown command. Type | to see the list.");

    /// <summary>Characters that belong to one token being completed (field names, values, IPs, wildcards).</summary>
    private static bool IsTokenChar(char c) =>
        !char.IsWhiteSpace(c) && c is not ('=' or '|' or '(' or ')' or ',' or '<' or '>' or '!' or '"' or '\'');

    /// <summary>Index of the opening quote if <paramref name="text"/> ends inside a quoted string.</summary>
    private static int? OpenQuoteAt(string text)
    {
        int? open = null;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (open is not null)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == text[open.Value])
                {
                    open = null;
                }
            }
            else if (c is '"' or '\'')
            {
                open = i;
            }
        }
        return open;
    }

    /// <summary>Index of the pipeline segment the text ends in, and where that segment starts.</summary>
    private static (int Index, int Start) Segment(string text)
    {
        var index = 0;
        var start = 0;
        char? quote = null;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quote is not null)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == quote)
                {
                    quote = null;
                }
            }
            else if (c is '"' or '\'')
            {
                quote = c;
            }
            else if (c == '|')
            {
                index++;
                start = i + 1;
            }
        }
        return (index, start);
    }

    /// <summary>If <c>text[..position]</c> ends with <c>field=</c> (or !=, &lt;, &gt;=, ...), the field name.</summary>
    private static string? FieldBeforeOperator(string text, int position)
    {
        var i = position;
        if (i == 0 || text[i - 1] is not ('=' or '<' or '>'))
        {
            return null;
        }
        while (i > 0 && text[i - 1] is '=' or '<' or '>' or '!')
        {
            i--;
        }
        var end = i;
        while (i > 0 && (Lexer.IsWordChar(text[i - 1]) || text[i - 1] is '.' or '-'))
        {
            i--;
        }
        return end > i ? text[i..end] : null;
    }

    private static string? FirstWord(string segment)
    {
        var trimmed = segment.TrimStart();
        var end = 0;
        while (end < trimmed.Length && Lexer.IsWordChar(trimmed[end]))
        {
            end++;
        }
        // Only a finished word (followed by something) counts as the command.
        return end > 0 && end < trimmed.Length ? trimmed[..end] : null;
    }

    private static List<string> Words(string segment) =>
        segment.Split([' ', '\t', ',', '(', ')'], StringSplitOptions.RemoveEmptyEntries).ToList();

    private static bool Unclosed(string text, char open, char close) =>
        text.Count(c => c == open) > text.Count(c => c == close);
}
