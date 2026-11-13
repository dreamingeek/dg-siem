using System.Globalization;

namespace DreaminGeek.Siem.Query;

/// <summary>Recursive-descent parser for the pipe language. Errors carry the character position.</summary>
public sealed class PipeParser : IQueryParser
{
    public const int MaxHead = 100_000;

    private static readonly string[] CompareOps = ["=", "!=", "<", "<=", ">", ">="];

    public PipelineNode Parse(string query)
    {
        ArgumentNullException.ThrowIfNull(query);
        var segments = Lexer.SplitPipes(query);
        var search = ParseSearch(segments[0].Text, segments[0].Offset);
        var commands = new List<CommandNode>();
        foreach (var (text, offset) in segments.Skip(1))
        {
            commands.Add(ParseCommand(text, offset));
        }
        return new PipelineNode(search, commands);
    }

    // ---------------------------------------------------------------- search clause

    private static SearchNode ParseSearch(string text, int offset)
    {
        var tokens = new Cursor(Lexer.Tokenize(text, offset, searchMode: true));
        if (tokens.AtEnd)
        {
            return new SearchNode(null);
        }
        var filter = SearchOr(tokens);
        tokens.ExpectEnd("search");
        return new SearchNode(filter is TermExpr { Text: "*", Quoted: false } ? null : filter);
    }

    private static Expr SearchOr(Cursor t)
    {
        var left = SearchAnd(t);
        while (t.Peek.Is("OR"))
        {
            var op = t.Next();
            left = new BinaryExpr(op.Position, "OR", left, SearchAnd(t));
        }
        return left;
    }

    private static Expr SearchAnd(Cursor t)
    {
        var left = SearchUnary(t);
        while (!t.AtEnd && !t.Peek.Is(")") && !t.Peek.Is("OR"))
        {
            var pos = t.Peek.Position;
            if (t.Peek.Is("AND"))
            {
                t.Next();
            }
            left = new BinaryExpr(pos, "AND", left, SearchUnary(t));
        }
        return left;
    }

    private static Expr SearchUnary(Cursor t)
    {
        if (t.Peek.Is("NOT"))
        {
            var not = t.Next();
            return new NotExpr(not.Position, SearchUnary(t));
        }
        if (t.Peek.Is("("))
        {
            t.Next();
            var inner = SearchOr(t);
            t.Expect(")");
            return inner;
        }

        var token = t.Next();
        if (token.Kind == TokenKind.Word && t.Peek.Kind == TokenKind.Op && CompareOps.Contains(t.Peek.Text))
        {
            var op = t.Next();
            var value = t.Next();
            if (value.Kind is not (TokenKind.Word or TokenKind.Quoted))
            {
                throw new QueryParseException($"Expected a value after '{token.Text}{op.Text}'.", value.Position);
            }
            return new BinaryExpr(op.Position, op.Text, new FieldRef(token.Position, token.Text),
                new Literal(value.Position, value.Kind == TokenKind.Quoted ? new QuotedValue(value.Text) : value.Text));
        }
        if (token.Kind == TokenKind.Word && t.Peek.Is("IN"))
        {
            t.Next();
            t.Expect("(");
            var options = new List<Expr>();
            do
            {
                var v = t.Next();
                if (v.Kind is not (TokenKind.Word or TokenKind.Quoted))
                {
                    throw new QueryParseException("Expected a value in IN (...).", v.Position);
                }
                options.Add(new Literal(v.Position, v.Kind == TokenKind.Quoted ? new QuotedValue(v.Text) : v.Text));
            }
            while (t.TryTake(","));
            t.Expect(")");
            return new InExpr(token.Position, new FieldRef(token.Position, token.Text), options);
        }
        return token.Kind switch
        {
            TokenKind.Word => new TermExpr(token.Position, token.Text, Quoted: false),
            TokenKind.Quoted => new TermExpr(token.Position, token.Text, Quoted: true),
            TokenKind.End => throw new QueryParseException("Search ended unexpectedly.", token.Position),
            _ => throw new QueryParseException($"Unexpected '{token.Text}'.", token.Position),
        };
    }

    // ---------------------------------------------------------------- commands

    private static CommandNode ParseCommand(string text, int offset)
    {
        var tokens = new Cursor(Lexer.Tokenize(text, offset, searchMode: false));
        var name = tokens.Next();
        if (name.Kind != TokenKind.Word)
        {
            throw new QueryParseException(name.Kind == TokenKind.End ? "Empty command after '|'." : "Expected a command name.", name.Position);
        }

        CommandNode command = name.Text.ToLowerInvariant() switch
        {
            "where" or "search" => new WhereCommand(name.Position, Expression(tokens)),
            "eval" => ParseEval(tokens, name.Position),
            "rex" => ParseRex(tokens, name.Position),
            "stats" => ParseStats(tokens, name.Position),
            "timechart" => ParseTimechart(tokens, name.Position),
            "sort" => ParseSort(tokens, name.Position),
            "head" => new HeadCommand(name.Position, tokens.AtEnd ? 10 : Count(tokens.Next())),
            "dedup" => new DedupCommand(name.Position, FieldList(tokens)),
            "table" => new TableCommand(name.Position, FieldList(tokens)),
            "fields" => ParseFields(tokens, name.Position),
            "top" => ParseTop(tokens, name.Position),
            "fieldsummary" => ParseFieldSummary(tokens, name.Position),
            _ => throw new QueryParseException(
                $"Unknown command '{name.Text}'. Available: where, eval, rex, stats, timechart, top, fieldsummary, sort, head, dedup, table, fields.", name.Position),
        };
        tokens.ExpectEnd(name.Text);
        return command;
    }

    private static EvalCommand ParseEval(Cursor t, int position)
    {
        var assignments = new List<(string, Expr)>();
        do
        {
            var field = FieldName(t);
            t.Expect("=");
            assignments.Add((field, Expression(t)));
        }
        while (t.TryTake(","));
        return new EvalCommand(position, assignments);
    }

    private static RexCommand ParseRex(Cursor t, int position)
    {
        var field = "message";
        if (t.Peek.IsKeyword("field") && t.PeekAt(1).Is("="))
        {
            t.Next();
            t.Next();
            field = FieldName(t);
        }
        var pattern = t.Next();
        if (pattern.Kind != TokenKind.Quoted)
        {
            throw new QueryParseException("rex needs a quoted regular expression with named groups, e.g. rex \"user=(?<user>\\w+)\".", pattern.Position);
        }
        return new RexCommand(position, field, pattern.Text);
    }

    private static StatsCommand ParseStats(Cursor t, int position)
    {
        var aggs = Aggregations(t, "stats");
        var by = new List<string>();
        if (t.Peek.IsKeyword("by"))
        {
            t.Next();
            by.AddRange(FieldList(t));
        }
        return new StatsCommand(position, aggs, by);
    }

    private static TimechartCommand ParseTimechart(Cursor t, int position)
    {
        TimeSpan? span = null;
        if (t.Peek.IsKeyword("span") && t.PeekAt(1).Is("="))
        {
            t.Next();
            t.Next();
            span = ParseSpan(t.Next());
        }
        var aggs = Aggregations(t, "timechart");
        string? by = null;
        if (t.Peek.IsKeyword("by"))
        {
            t.Next();
            by = FieldName(t);
        }
        return new TimechartCommand(position, span, aggs, by);
    }

    private static SortCommand ParseSort(Cursor t, int position)
    {
        var keys = new List<SortKey>();
        do
        {
            var descending = false;
            if (t.TryTake("-"))
            {
                descending = true;
            }
            else
            {
                t.TryTake("+");
            }
            var field = FieldName(t);
            if (t.Peek.IsKeyword("desc"))
            {
                t.Next();
                descending = true;
            }
            else if (t.Peek.IsKeyword("asc"))
            {
                t.Next();
            }
            keys.Add(new SortKey(field, descending));
            t.TryTake(",");
        }
        while (!t.AtEnd);
        return new SortCommand(position, keys);
    }

    private static FieldsCommand ParseFields(Cursor t, int position)
    {
        var exclude = t.TryTake("-");
        if (!exclude)
        {
            t.TryTake("+");
        }
        return new FieldsCommand(position, FieldList(t), exclude);
    }

    private static FieldSummaryCommand ParseFieldSummary(Cursor t, int position)
    {
        var max = 5;
        if (t.Peek.IsKeyword("maxvals") && t.PeekAt(1).Is("="))
        {
            t.Next();
            t.Next();
            max = Math.Min(Count(t.Next()), 100);
        }
        return new FieldSummaryCommand(position, t.AtEnd ? [] : FieldList(t), max);
    }

    private static TopCommand ParseTop(Cursor t, int position)
    {
        var limit = 10;
        if (t.Peek.IsKeyword("limit") && t.PeekAt(1).Is("="))
        {
            t.Next();
            t.Next();
            limit = Count(t.Next());
        }
        var field = FieldName(t);
        string? by = null;
        if (t.Peek.IsKeyword("by"))
        {
            t.Next();
            by = FieldName(t);
        }
        if (t.Peek.IsKeyword("limit") && t.PeekAt(1).Is("="))
        {
            t.Next();
            t.Next();
            limit = Count(t.Next());
        }
        return new TopCommand(position, field, by, limit);
    }

    private static List<Aggregation> Aggregations(Cursor t, string command)
    {
        var aggs = new List<Aggregation>();
        while (!t.AtEnd && !t.Peek.IsKeyword("by"))
        {
            var fn = t.Next();
            if (fn.Kind != TokenKind.Word)
            {
                throw new QueryParseException($"Expected an aggregation like count(), dc(field), avg(field) in {command}.", fn.Position);
            }
            string? field = null;
            if (t.TryTake("("))
            {
                if (!t.Peek.Is(")"))
                {
                    field = FieldName(t);
                }
                t.Expect(")");
            }
            string? alias = null;
            if (t.Peek.IsKeyword("as"))
            {
                t.Next();
                alias = FieldName(t);
            }
            aggs.Add(new Aggregation(fn.Text.ToLowerInvariant(), field, alias));
            t.TryTake(",");
        }
        if (aggs.Count == 0)
        {
            throw new QueryParseException($"{command} needs at least one aggregation, e.g. count().", t.Peek.Position);
        }
        return aggs;
    }

    private static List<string> FieldList(Cursor t)
    {
        var fields = new List<string>();
        do
        {
            fields.Add(FieldName(t));
        }
        while (t.TryTake(",") || (!t.AtEnd && t.Peek.Kind == TokenKind.Word && !t.Peek.IsKeyword("by") && !t.Peek.IsKeyword("limit")));
        return fields;
    }

    private static string FieldName(Cursor t)
    {
        var token = t.Next();
        if (token.Kind is TokenKind.Word or TokenKind.Quoted && token.Text.Length > 0)
        {
            return token.Text;
        }
        throw new QueryParseException(token.Kind == TokenKind.End ? "Expected a field name." : $"Expected a field name, got '{token.Text}'.", token.Position);
    }

    private static int Count(Token token)
    {
        if (!int.TryParse(token.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n < 1)
        {
            throw new QueryParseException($"Expected a positive whole number, got '{token.Text}'.", token.Position);
        }
        return Math.Min(n, MaxHead);
    }

    /// <summary><c>30s</c>, <c>5m</c>, <c>1h</c>, <c>1d</c>, <c>1w</c>.</summary>
    public static TimeSpan ParseSpan(Token token)
    {
        var text = token.Text;
        if (text.Length >= 2 && int.TryParse(text[..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0)
        {
            TimeSpan? span = text[^1] switch
            {
                's' => TimeSpan.FromSeconds(n),
                'm' => TimeSpan.FromMinutes(n),
                'h' => TimeSpan.FromHours(n),
                'd' => TimeSpan.FromDays(n),
                'w' => TimeSpan.FromDays(7 * n),
                _ => null,
            };
            if (span is { } s && s >= TimeSpan.FromSeconds(1))
            {
                return s;
            }
        }
        throw new QueryParseException($"Invalid span '{text}'. Use e.g. 30s, 5m, 1h, 1d.", token.Position);
    }

    // ---------------------------------------------------------------- expressions (where / eval)

    public static Expr Expression(Cursor t) => Or(t);

    private static Expr Or(Cursor t)
    {
        var left = And(t);
        while (t.Peek.IsKeyword("OR"))
        {
            var op = t.Next();
            left = new BinaryExpr(op.Position, "OR", left, And(t));
        }
        return left;
    }

    private static Expr And(Cursor t)
    {
        var left = Not(t);
        while (t.Peek.IsKeyword("AND"))
        {
            var op = t.Next();
            left = new BinaryExpr(op.Position, "AND", left, Not(t));
        }
        return left;
    }

    private static Expr Not(Cursor t)
    {
        if (t.Peek.IsKeyword("NOT"))
        {
            var op = t.Next();
            return new NotExpr(op.Position, Not(t));
        }
        return Comparison(t);
    }

    private static Expr Comparison(Cursor t)
    {
        var left = Additive(t);
        if (t.Peek.Kind == TokenKind.Op && CompareOps.Contains(t.Peek.Text))
        {
            var op = t.Next();
            return new BinaryExpr(op.Position, op.Text, left, Additive(t));
        }
        var negated = t.Peek.IsKeyword("NOT") && t.PeekAt(1).IsKeyword("IN");
        if (negated || t.Peek.IsKeyword("IN"))
        {
            var pos = t.Peek.Position;
            if (negated)
            {
                t.Next();
            }
            t.Next();
            t.Expect("(");
            var options = new List<Expr>();
            do
            {
                options.Add(Additive(t));
            }
            while (t.TryTake(","));
            t.Expect(")");
            Expr inExpr = new InExpr(pos, left, options);
            return negated ? new NotExpr(pos, inExpr) : inExpr;
        }
        return left;
    }

    private static Expr Additive(Cursor t)
    {
        var left = Multiplicative(t);
        while (t.Peek.Kind == TokenKind.Op && t.Peek.Text is "+" or "-" or ".")
        {
            var op = t.Next();
            left = new BinaryExpr(op.Position, op.Text, left, Multiplicative(t));
        }
        return left;
    }

    private static Expr Multiplicative(Cursor t)
    {
        var left = Unary(t);
        while (t.Peek.Kind == TokenKind.Op && t.Peek.Text is "*" or "/" or "%")
        {
            var op = t.Next();
            left = new BinaryExpr(op.Position, op.Text, left, Unary(t));
        }
        return left;
    }

    private static Expr Unary(Cursor t)
    {
        if (t.Peek.Is("-"))
        {
            var op = t.Next();
            return new NegateExpr(op.Position, Unary(t));
        }
        return Primary(t);
    }

    private static Expr Primary(Cursor t)
    {
        var token = t.Next();
        switch (token.Kind)
        {
            case TokenKind.Number:
                return new Literal(token.Position, Lexer.ParseNumber(token));
            case TokenKind.Quoted:
                return new Literal(token.Position, token.Text);
            case TokenKind.Op when token.Text == "(":
                var inner = Expression(t);
                t.Expect(")");
                return inner;
            case TokenKind.Word when t.Peek.Is("("):
                t.Next();
                var args = new List<Expr>();
                if (!t.Peek.Is(")"))
                {
                    do
                    {
                        args.Add(Expression(t));
                    }
                    while (t.TryTake(","));
                }
                t.Expect(")");
                return new CallExpr(token.Position, token.Text.ToLowerInvariant(), args);
            case TokenKind.Word:
                return new FieldRef(token.Position, token.Text);
            case TokenKind.End:
                throw new QueryParseException("Expression ended unexpectedly.", token.Position);
            default:
                throw new QueryParseException($"Unexpected '{token.Text}'.", token.Position);
        }
    }

    /// <summary>Token cursor with one-token lookahead helpers.</summary>
    public sealed class Cursor(List<Token> tokens)
    {
        private int _i;

        public Token Peek => tokens[Math.Min(_i, tokens.Count - 1)];

        public bool AtEnd => Peek.Kind == TokenKind.End;

        public Token PeekAt(int ahead) => tokens[Math.Min(_i + ahead, tokens.Count - 1)];

        public Token Next() => tokens[Math.Min(_i++, tokens.Count - 1)];

        public bool TryTake(string op)
        {
            if (Peek.Is(op))
            {
                _i++;
                return true;
            }
            return false;
        }

        public void Expect(string op)
        {
            var token = Next();
            if (!token.Is(op))
            {
                throw new QueryParseException(token.Kind == TokenKind.End ? $"Expected '{op}' before the end." : $"Expected '{op}', got '{token.Text}'.", token.Position);
            }
        }

        public void ExpectEnd(string context)
        {
            if (!AtEnd)
            {
                throw new QueryParseException($"Unexpected '{Peek.Text}' in {context}.", Peek.Position);
            }
        }
    }
}

/// <summary>A value that was quoted in the search clause: no wildcards, always a string.</summary>
public sealed record QuotedValue(string Text)
{
    public override string ToString() => Text;
}
