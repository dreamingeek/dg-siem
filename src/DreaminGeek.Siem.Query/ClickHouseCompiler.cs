using System.Globalization;
using System.Net;
using System.Text;

namespace DreaminGeek.Siem.Query;

/// <summary>
/// Compiles a <see cref="PipelineNode"/> into one parameterized ClickHouse query.
/// <para>
/// Safety rules: every query reads only <c>{db}.events</c>, always filtered to
/// <see cref="QueryRequest.TenantIds"/> and the requested time range; every user-supplied value
/// (search terms, literals, map keys, regexes) is a typed <c>{pN:Type}</c> parameter; field names
/// are validated and only ever appear as backtick-quoted aliases; functions come from an allowlist.
/// </para>
/// <para>
/// Commands accumulate into a "stage" (one SELECT). A command that can't be expressed in the
/// current stage, e.g. a <c>where</c> after <c>stats</c>, wraps the stage in a subquery.
/// </para>
/// </summary>
public sealed class ClickHouseCompiler(string database, CompilerOptions? options = null) : IQueryCompiler
{
    private readonly CompilerOptions _options = options ?? new CompilerOptions();

    public CompiledQuery Compile(PipelineNode pipeline, QueryRequest request)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(request);
        if (request.TenantIds.Count == 0)
        {
            throw new QueryParseException("You don't have access to any tenants.", 0);
        }
        if (request.To <= request.From)
        {
            throw new QueryParseException("The time range is empty.", 0);
        }
        return new Compilation(database, _options, request).Run(pipeline);
    }

    /// <summary>
    /// Names of the extra (non-promoted) fields present in the caller's events, most common first:
    /// the field list for autocomplete. Tenant- and time-scoped like any search.
    /// </summary>
    public CompiledQuery CompileFieldNames(QueryRequest request, int limit = 500)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.TenantIds.Count == 0)
        {
            throw new QueryParseException("You don't have access to any tenants.", 0);
        }
        return new Compilation(database, _options, request).RunFieldNames(Math.Clamp(limit, 1, 5000));
    }

    private sealed class Stage
    {
        /// <summary>Null = the events table (with the tenant/time filter); otherwise a subquery.</summary>
        public string? Source { get; init; }
        public bool EventMode => Source is null;

        /// <summary>Event mode: computed fields (eval/rex), inlined. Table mode: the subquery's columns.</summary>
        public Dictionary<string, SqlExpr> Fields { get; } = new(StringComparer.Ordinal);
        public List<string> FieldOrder { get; } = [];

        public List<string> Where { get; } = [];
        /// <summary>Explicit select list (aggregation or projection). Null = default columns.</summary>
        public List<(string Alias, SqlExpr Expr)>? Select { get; set; }
        public List<string> GroupBy { get; } = [];
        public List<string> OrderBy { get; } = [];
        public List<string> LimitBy { get; } = [];
        public int? LimitByCount { get; set; }
        public int? Limit { get; set; }
        /// <summary>ARRAY JOIN clause (fieldsummary), rendered between FROM and WHERE.</summary>
        public string? ArrayJoin { get; set; }
        public bool Aggregated { get; set; }
        public ResultShape Shape { get; set; } = ResultShape.Events;

        public bool Shaped => Aggregated || Limit is not null || LimitBy.Count > 0 || OrderBy.Count > 0 || Select is not null;
    }

    private sealed class Compilation(string database, CompilerOptions options, QueryRequest request)
    {
        private readonly Dictionary<string, object> _params = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _paramTypes = new(StringComparer.Ordinal);
        private Stage _stage = new();

        private void AddScope()
        {
            _stage.Where.Add($"tenant_id IN {Param(request.TenantIds.ToArray(), "Array(String)")}");
            _stage.Where.Add($"timestamp >= {Param(request.From.UtcDateTime, "DateTime64(3, 'UTC')")}");
            _stage.Where.Add($"timestamp < {Param(request.To.UtcDateTime, "DateTime64(3, 'UTC')")}");
        }

        public CompiledQuery RunFieldNames(int limit)
        {
            AddScope();
            _stage.ArrayJoin = "mapKeys(fields) AS _k";
            _stage.Select = [("field", new SqlExpr("_k", SqlType.String)), ("count", new SqlExpr("count()", SqlType.Number))];
            _stage.GroupBy.Add("_k");
            _stage.OrderBy.Add("`count` DESC");
            _stage.Aggregated = true;
            _stage.Shape = ResultShape.Table;
            _stage.Limit = limit;
            var (sql, columns) = Render(_stage);
            return new CompiledQuery(sql, _params, ResultShape.Table, columns, limit, _paramTypes) { TenantIds = request.TenantIds };
        }

        public CompiledQuery Run(PipelineNode pipeline)
        {
            AddScope();
            if (pipeline.Search.Filter is { } filter)
            {
                _stage.Where.Add(Bool(Compile(filter, search: true)));
            }

            foreach (var command in pipeline.Commands)
            {
                Apply(command);
            }

            // Final shaping: default order and a hard row cap.
            var final = _stage;
            if (final.OrderBy.Count == 0)
            {
                if (final.EventMode && !final.Aggregated)
                {
                    final.OrderBy.Add("timestamp DESC");
                }
                else if (final.Aggregated && final.GroupBy.Count > 0 && final.Shape != ResultShape.Timechart)
                {
                    final.OrderBy.AddRange(final.GroupBy.Select(g => $"{g} ASC")); // by-fields, in order
                }
            }
            var limit = final.Limit ?? (final.EventMode && !final.Aggregated ? options.DefaultEventLimit : options.MaxRows);
            final.Limit = Math.Min(limit, options.MaxRows);

            var (sql, columns) = Render(final);
            return new CompiledQuery(sql, _params, final.Shape, columns, final.Limit.Value, _paramTypes) { TenantIds = request.TenantIds };
        }

        // ------------------------------------------------------------ commands

        private void Apply(CommandNode command)
        {
            switch (command)
            {
                case WhereCommand where:
                    EnsureUnshaped();
                    _stage.Where.Add(Bool(Compile(where.Condition, search: false)));
                    break;

                case EvalCommand eval:
                    EnsureUnshaped();
                    foreach (var (field, value) in eval.Assignments)
                    {
                        AddComputed(ValidName(field, eval.Position), Compile(value, search: false));
                    }
                    break;

                case RexCommand rex:
                    EnsureUnshaped();
                    CompileRex(rex);
                    break;

                case StatsCommand stats:
                    EnsureUnshaped();
                    CompileStats(stats.Aggregations, stats.By, stats.Position);
                    break;

                case TopCommand top:
                    EnsureUnshaped();
                    CompileTop(top);
                    break;

                case TimechartCommand chart:
                    EnsureUnshaped();
                    CompileTimechart(chart);
                    break;

                case FieldSummaryCommand summary:
                    EnsureUnshaped();
                    CompileFieldSummary(summary);
                    break;

                case SortCommand sort:
                    if (_stage.Limit is not null || _stage.LimitBy.Count > 0)
                    {
                        Wrap();
                    }
                    _stage.OrderBy.Clear();
                    foreach (var key in sort.Keys)
                    {
                        _stage.OrderBy.Add($"{OrderTarget(key.Field, sort.Position)} {(key.Descending ? "DESC" : "ASC")}");
                    }
                    break;

                case HeadCommand head:
                    _stage.Limit = _stage.Limit is { } existing ? Math.Min(existing, head.Count) : head.Count;
                    break;

                case DedupCommand dedup:
                    if (_stage.Limit is not null || _stage.LimitBy.Count > 0)
                    {
                        Wrap();
                    }
                    foreach (var field in dedup.Fields)
                    {
                        _stage.LimitBy.Add(Resolve(field, dedup.Position).Sql);
                    }
                    _stage.LimitByCount = 1;
                    break;

                case TableCommand table:
                    Project(table.Fields, exclude: false, table.Position);
                    break;

                case FieldsCommand fields:
                    Project(fields.Fields, fields.Exclude, fields.Position);
                    break;

                default:
                    throw new QueryParseException($"Command not supported yet: {command.GetType().Name}.", command.Position);
            }
        }

        /// <summary>Row-changing commands after stats/sort/head/dedup/table need a fresh SELECT around the current one.</summary>
        private void EnsureUnshaped()
        {
            if (_stage.Shaped)
            {
                Wrap();
            }
        }

        private void Wrap()
        {
            var (sql, columns) = Render(_stage);
            var types = OutputTypes(_stage);
            var outer = new Stage { Source = $"({sql})", Shape = _stage.Shape == ResultShape.Events ? ResultShape.Table : _stage.Shape };
            foreach (var column in columns)
            {
                outer.Fields[column] = new SqlExpr(Quote(column), types.GetValueOrDefault(column, SqlType.String));
                outer.FieldOrder.Add(column);
            }
            _stage = outer;
        }

        private void AddComputed(string name, SqlExpr expr)
        {
            if (_stage.EventMode)
            {
                _stage.Fields[name] = expr; // inlined wherever referenced
                if (!_stage.FieldOrder.Contains(name))
                {
                    _stage.FieldOrder.Add(name);
                }
            }
            else
            {
                // Table mode: add a column on top of the subquery's columns.
                var select = _stage.FieldOrder.Where(f => f != name).Select(f => (f, _stage.Fields[f])).ToList();
                select.Add((name, expr));
                var types = select.ToDictionary(s => s.Item1, s => s.Item2.Type);
                _stage.Select = select;
                Wrap();
                _stage.Fields[name] = new SqlExpr(Quote(name), types[name]);
            }
        }

        private void CompileRex(RexCommand rex)
        {
            var (pattern, groups) = RexPattern.Convert(rex.Pattern, rex.Position);
            var source = $"toString({Resolve(rex.SourceField, rex.Position).Sql})";
            var groupsExpr = $"extractGroups({source}, {Param(pattern, "String")})";
            foreach (var (name, index) in groups)
            {
                AddComputed(ValidName(name, rex.Position), new SqlExpr($"arrayElement({groupsExpr}, {index.ToString(CultureInfo.InvariantCulture)})", SqlType.String));
            }
        }

        private void CompileStats(IReadOnlyList<Aggregation> aggregations, IReadOnlyList<string> by, int position)
        {
            var select = new List<(string, SqlExpr)>();
            foreach (var field in by)
            {
                var name = OutputName(field);
                var expr = Resolve(field, position);
                select.Add((name, expr));
                _stage.GroupBy.Add(expr.Sql); // expressions, not aliases: an alias can collide with a real column
            }
            foreach (var agg in aggregations)
            {
                select.Add((ValidName(agg.Alias ?? OutputName(agg), position), CompileAggregation(agg, position)));
            }
            _stage.Select = select;
            _stage.Aggregated = true;
            _stage.Shape = ResultShape.Table;
        }

        private void CompileTop(TopCommand top)
        {
            var field = OutputName(top.Field);
            var select = new List<(string, SqlExpr)>();
            string? by = null;
            string? byExpr = null;
            if (top.By is not null)
            {
                by = OutputName(top.By);
                byExpr = Resolve(top.By, top.Position).Sql;
                select.Add((by, new SqlExpr(byExpr, SqlType.String)));
                _stage.GroupBy.Add(byExpr);
            }
            var fieldExpr = Resolve(top.Field, top.Position);
            select.Add((field, fieldExpr));
            _stage.GroupBy.Add(fieldExpr.Sql);
            select.Add(("count", new SqlExpr("count()", SqlType.Number)));
            var partition = byExpr is null ? string.Empty : $"PARTITION BY {byExpr}";
            select.Add(("percent", new SqlExpr($"round(100 * count() / sum(count()) OVER ({partition}), 2)", SqlType.Number)));
            _stage.Select = select;
            _stage.Aggregated = true;
            _stage.Shape = ResultShape.Table;
            if (by is not null)
            {
                _stage.OrderBy.Add($"{Quote(by)} ASC");
                _stage.LimitBy.Add(byExpr!);
                _stage.LimitByCount = top.Limit;
                _stage.OrderBy.Add("`count` DESC");
            }
            else
            {
                _stage.OrderBy.Add("`count` DESC");
                _stage.Limit = top.Limit;
            }
        }

        /// <summary>
        /// One pass over the events: ARRAY JOIN each event into (field, value) pairs, then count the
        /// top values per field. Output columns: field, value, count.
        /// </summary>
        private void CompileFieldSummary(FieldSummaryCommand summary)
        {
            var fields = summary.Fields.Count > 0
                ? summary.Fields.Select(OutputName).Distinct(StringComparer.Ordinal).ToList()
                // Defaults: after a subquery (e.g. "| head 50 | fieldsummary") only the columns that exist.
                : FieldCatalog.DefaultSummaryFields.Where(f => _stage.EventMode || _stage.Fields.ContainsKey(f)).ToList();
            if (fields.Count == 0)
            {
                throw new QueryParseException("fieldsummary: none of the fields exist at this point; name them, e.g. fieldsummary host.name.", summary.Position);
            }
            var pairs = fields.Select(f =>
            {
                var expr = Resolve(f, summary.Position);
                // Missing values ('' or a 0 port) are skipped, not counted as a value.
                return $"tuple({Param(f, "String")}, if({Present(expr)}, toString({expr.Sql}), ''))";
            });
            _stage.ArrayJoin = $"[{string.Join(", ", pairs)}] AS _kv";
            _stage.Where.Add("notEmpty(_kv.2)");
            _stage.Select =
            [
                ("field", new SqlExpr("_kv.1", SqlType.String)),
                ("value", new SqlExpr("_kv.2", SqlType.String)),
                ("count", new SqlExpr("count()", SqlType.Number)),
            ];
            _stage.GroupBy.AddRange(["_kv.1", "_kv.2"]);
            _stage.OrderBy.AddRange(["`field` ASC", "`count` DESC"]);
            _stage.LimitBy.Add("_kv.1");
            _stage.LimitByCount = summary.MaxValues;
            _stage.Aggregated = true;
            _stage.Shape = ResultShape.Table;
        }

        private void CompileTimechart(TimechartCommand chart)
        {
            if (!_stage.EventMode)
            {
                throw new QueryParseException("timechart needs raw events: put it before stats/top/table.", chart.Position);
            }
            var span = chart.Span ?? AutoSpan(request.To - request.From);
            var bucket = $"toStartOfInterval(timestamp, {Interval(span)})";
            var select = new List<(string, SqlExpr)> { ("_time", new SqlExpr(bucket, SqlType.DateTime)) };
            _stage.GroupBy.Add(bucket);
            if (chart.By is not null)
            {
                var name = OutputName(chart.By);
                var byExpr = Resolve(chart.By, chart.Position);
                select.Add((name, byExpr));
                _stage.GroupBy.Add(byExpr.Sql);
            }
            foreach (var agg in chart.Aggregations)
            {
                select.Add((ValidName(agg.Alias ?? OutputName(agg), chart.Position), CompileAggregation(agg, chart.Position)));
            }
            _stage.Select = select;
            _stage.Aggregated = true;
            _stage.Shape = ResultShape.Timechart;
            _stage.OrderBy.Add("`_time` ASC");
            if (chart.By is not null)
            {
                _stage.OrderBy.Add($"{Quote(OutputName(chart.By))} ASC");
            }
        }

        private SqlExpr CompileAggregation(Aggregation agg, int position)
        {
            if (agg.Field is null)
            {
                return agg.Function switch
                {
                    "count" => new SqlExpr("count()", SqlType.Number),
                    _ => throw new QueryParseException($"{agg.Function}() needs a field, e.g. {agg.Function}(network.bytes).", position),
                };
            }

            var field = Resolve(agg.Field, position);
            var present = Present(field);
            var number = ToNumber(field);
            if (agg.Function.Length == 3 && agg.Function[0] == 'p' &&
                int.TryParse(agg.Function.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var pct) && pct is > 0 and < 100)
            {
                return new SqlExpr($"quantile({(pct / 100.0).ToString("0.##", CultureInfo.InvariantCulture)})({number})", SqlType.Number);
            }
            return agg.Function switch
            {
                "count" => new SqlExpr($"countIf({present})", SqlType.Number),
                "dc" or "distinct_count" => new SqlExpr($"uniqExactIf({field.Sql}, {present})", SqlType.Number),
                "sum" => new SqlExpr($"sum({number})", SqlType.Number),
                "avg" or "mean" => new SqlExpr($"avg({number})", SqlType.Number),
                "min" => new SqlExpr($"min({number})", SqlType.Number),
                "max" => new SqlExpr($"max({number})", SqlType.Number),
                "median" => new SqlExpr($"median({number})", SqlType.Number),
                "values" => new SqlExpr($"arraySort(groupUniqArrayIf(100)(toString({field.Sql}), {present}))", SqlType.Array),
                "earliest" or "first" => RequireTime(new SqlExpr($"argMin({field.Sql}, timestamp)", field.Type), agg, position),
                "latest" or "last" => RequireTime(new SqlExpr($"argMax({field.Sql}, timestamp)", field.Type), agg, position),
                _ => throw new QueryParseException(
                    $"Unknown aggregation '{agg.Function}'. Use count, dc, sum, avg, min, max, median, p50/p90/p95/p99, values, earliest, latest.", position),
            };
        }

        private SqlExpr RequireTime(SqlExpr expr, Aggregation agg, int position) =>
            _stage.EventMode ? expr : throw new QueryParseException($"{agg.Function}() needs raw events: use it before other stats.", position);

        private void Project(IReadOnlyList<string> fields, bool exclude, int position)
        {
            if (_stage.Aggregated || _stage.Select is not null)
            {
                Wrap();
            }

            List<string> names;
            if (exclude)
            {
                var drop = fields.Select(OutputName).ToHashSet(StringComparer.Ordinal);
                names = CurrentColumns().Where(c => !drop.Contains(c)).ToList();
            }
            else
            {
                names = fields.Select(OutputName).Distinct(StringComparer.Ordinal).ToList();
            }
            _stage.Select = names.Select(n => (ValidName(n, position), Resolve(n, position))).ToList();
            if (!_stage.EventMode && _stage.Shape == ResultShape.Events)
            {
                _stage.Shape = ResultShape.Table;
            }
        }

        // ------------------------------------------------------------ expressions

        private SqlExpr Compile(Expr expr, bool search) => expr switch
        {
            TermExpr term => CompileTerm(term),
            FieldRef field => Resolve(field.Name, field.Position),
            Literal literal => CompileLiteral(literal),
            NotExpr not => new SqlExpr($"NOT ({Bool(Compile(not.Operand, search))})", SqlType.Bool),
            NegateExpr neg => new SqlExpr($"-({ToNumber(Compile(neg.Operand, search))})", SqlType.Number),
            InExpr inExpr => CompileIn(inExpr, search),
            CallExpr call => CompileCall(call),
            BinaryExpr { Op: "AND" or "OR" } b =>
                new SqlExpr($"({Bool(Compile(b.Left, search))} {b.Op} {Bool(Compile(b.Right, search))})", SqlType.Bool),
            BinaryExpr { Op: "=" or "!=" or "<" or "<=" or ">" or ">=" } b when search && b.Left is FieldRef f && b.Right is Literal l =>
                CompileSearchComparison(f, b.Op, l),
            BinaryExpr { Op: "=" or "!=" or "<" or "<=" or ">" or ">=" } b => CompileComparison(b, search),
            BinaryExpr { Op: "." } b => new SqlExpr($"concat(toString({Compile(b.Left, search).Sql}), toString({Compile(b.Right, search).Sql}))", SqlType.String),
            BinaryExpr { Op: "+" or "-" or "*" or "/" or "%" } b =>
                new SqlExpr($"({ToNumber(Compile(b.Left, search))} {b.Op} {ToNumber(Compile(b.Right, search))})", SqlType.Number),
            _ => throw new QueryParseException("Unsupported expression.", expr.Position),
        };

        /// <summary>Search terms match anywhere in the raw line, case-insensitively.</summary>
        private SqlExpr CompileTerm(TermExpr term)
        {
            var text = term.Text;
            if (!term.Quoted && text == "*")
            {
                return new SqlExpr("1", SqlType.Bool);
            }
            if (!term.Quoted && text.Contains('*', StringComparison.Ordinal))
            {
                var pattern = (text.StartsWith('*') ? "" : "%") + LikePattern(text) + (text.EndsWith('*') ? "" : "%");
                return new SqlExpr($"raw ILIKE {Param(pattern, "String")}", SqlType.Bool);
            }
            if (text.Length > 0 && text.All(c => char.IsAsciiLetterOrDigit(c) || c > 127))
            {
                // A single token (ClickHouse splits tokens on any non-alphanumeric ASCII, including '_'):
                // can use the token bloom-filter index.
                return new SqlExpr($"hasTokenCaseInsensitive(raw, {Param(text, "String")})", SqlType.Bool);
            }
            return new SqlExpr($"(positionCaseInsensitiveUTF8(raw, {Param(text, "String")}) > 0)", SqlType.Bool);
        }

        /// <summary><c>field=value</c> in the search clause: wildcards, CIDR ranges and numbers handled by field type.</summary>
        private SqlExpr CompileSearchComparison(FieldRef fieldRef, string op, Literal literal)
        {
            var field = Resolve(fieldRef.Name, fieldRef.Position);
            var quoted = literal.Value is QuotedValue;
            var text = literal.Value.ToString() ?? string.Empty;

            if (op is "=" or "!=" && !quoted)
            {
                if (text == "*")
                {
                    // field=* means "has a value" (as in Splunk); field!=* means it's empty.
                    var present = field.Type == SqlType.Number ? $"{field.Sql} != 0" : $"toString({field.Sql}) != ''";
                    return new SqlExpr(op == "=" ? present : $"NOT ({present})", SqlType.Bool);
                }
                if (text.Contains('*', StringComparison.Ordinal))
                {
                    var like = $"toString({field.Sql}) ILIKE {Param(LikePattern(text), "String")}";
                    return new SqlExpr(op == "=" ? like : $"NOT ({like})", SqlType.Bool);
                }
                if (text.Contains('/', StringComparison.Ordinal) && IPNetwork.TryParse(text, out _))
                {
                    var range = CidrMatch(field, Param(text, "String"));
                    return new SqlExpr(op == "=" ? range : $"NOT ({range})", SqlType.Bool);
                }
            }

            if (!quoted && field.Type == SqlType.Number && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var number))
            {
                return new SqlExpr($"{field.Sql} {op} {Param(number, "Float64")}", SqlType.Bool);
            }
            if (field.Type == SqlType.DateTime)
            {
                return new SqlExpr($"{field.Sql} {op} parseDateTime64BestEffort({Param(text, "String")}, 3, 'UTC')", SqlType.Bool);
            }
            if (op is "<" or "<=" or ">" or ">=" && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var n))
            {
                return new SqlExpr($"{ToNumber(field)} {op} {Param(n, "Float64")}", SqlType.Bool);
            }
            return new SqlExpr($"toString({field.Sql}) {op} {Param(text, "String")}", SqlType.Bool);
        }

        private SqlExpr CompileComparison(BinaryExpr b, bool search)
        {
            var left = Compile(b.Left, search);
            var right = Compile(b.Right, search);
            string l = left.Sql, r = right.Sql;
            if (left.Type == SqlType.Number || right.Type == SqlType.Number)
            {
                l = ToNumber(left);
                r = ToNumber(right);
            }
            else if (left.Type == SqlType.DateTime && right.Type == SqlType.String)
            {
                r = $"parseDateTime64BestEffortOrNull({r}, 3, 'UTC')";
            }
            else if (right.Type == SqlType.DateTime && left.Type == SqlType.String)
            {
                l = $"parseDateTime64BestEffortOrNull({l}, 3, 'UTC')";
            }
            else if (left.Type == SqlType.Bool || right.Type == SqlType.Bool)
            {
                l = Bool(left);
                r = Bool(right);
            }
            return new SqlExpr($"({l} {b.Op} {r})", SqlType.Bool);
        }

        private SqlExpr CompileIn(InExpr inExpr, bool search)
        {
            var value = Compile(inExpr.Value, search);
            var options = inExpr.Options.Select(o => o is Literal { Value: var v } && search
                ? Param(v.ToString() ?? string.Empty, "String")
                : $"toString({Compile(o, search).Sql})");
            return new SqlExpr($"(toString({value.Sql}) IN ({string.Join(", ", options)}))", SqlType.Bool);
        }

        private SqlExpr CompileLiteral(Literal literal) => literal.Value switch
        {
            double d => new SqlExpr(Param(d, "Float64"), SqlType.Number),
            QuotedValue q => new SqlExpr(Param(q.Text, "String"), SqlType.String),
            string s => new SqlExpr(Param(s, "String"), SqlType.String),
            _ => throw new QueryParseException("Unsupported literal.", literal.Position),
        };

        private SqlExpr CompileCall(CallExpr call)
        {
            SqlExpr Arg(int i) => i < call.Args.Count
                ? Compile(call.Args[i], search: false)
                : throw new QueryParseException($"{call.Function}() needs at least {i + 1} argument(s).", call.Position);
            void Arity(int min, int max)
            {
                if (call.Args.Count < min || call.Args.Count > max)
                {
                    throw new QueryParseException(
                        min == max ? $"{call.Function}() takes {min} argument(s)." : $"{call.Function}() takes {min}-{max} arguments.", call.Position);
                }
            }

            switch (call.Function)
            {
                case "lower":
                    Arity(1, 1);
                    return new SqlExpr($"lowerUTF8(toString({Arg(0).Sql}))", SqlType.String);
                case "upper":
                    Arity(1, 1);
                    return new SqlExpr($"upperUTF8(toString({Arg(0).Sql}))", SqlType.String);
                case "len" or "length":
                    Arity(1, 1);
                    return new SqlExpr($"lengthUTF8(toString({Arg(0).Sql}))", SqlType.Number);
                case "tostring":
                    Arity(1, 1);
                    return new SqlExpr($"toString({Arg(0).Sql})", SqlType.String);
                case "tonumber":
                    Arity(1, 1);
                    return new SqlExpr(ToNumber(Arg(0)), SqlType.Number);
                case "round":
                    Arity(1, 2);
                    var digits = call.Args.Count == 2 && call.Args[1] is Literal { Value: double dd } ? (int)dd : 0;
                    return new SqlExpr($"round({ToNumber(Arg(0))}, {Math.Clamp(digits, 0, 10).ToString(CultureInfo.InvariantCulture)})", SqlType.Number);
                case "abs":
                    Arity(1, 1);
                    return new SqlExpr($"abs({ToNumber(Arg(0))})", SqlType.Number);
                case "substr":
                    Arity(2, 3);
                    return new SqlExpr(call.Args.Count == 3
                        ? $"substringUTF8(toString({Arg(0).Sql}), toInt64({ToNumber(Arg(1))}), toInt64({ToNumber(Arg(2))}))"
                        : $"substringUTF8(toString({Arg(0).Sql}), toInt64({ToNumber(Arg(1))}))", SqlType.String);
                case "replace":
                    Arity(3, 3);
                    return new SqlExpr($"replaceRegexpAll(toString({Arg(0).Sql}), {Arg(1).Sql}, toString({Arg(2).Sql}))", SqlType.String);
                case "if":
                    Arity(3, 3);
                    var a = Arg(1);
                    var b = Arg(2);
                    return a.Type == SqlType.Number && b.Type == SqlType.Number
                        ? new SqlExpr($"if({Bool(Arg(0))}, {a.Sql}, {b.Sql})", SqlType.Number)
                        : new SqlExpr($"if({Bool(Arg(0))}, toString({a.Sql}), toString({b.Sql}))", SqlType.String);
                case "coalesce":
                    if (call.Args.Count < 2)
                    {
                        throw new QueryParseException("coalesce() takes at least 2 arguments.", call.Position);
                    }
                    var parts = call.Args.Select(arg => $"toString({Compile(arg, search: false).Sql})").ToList();
                    var sb = new StringBuilder("multiIf(");
                    foreach (var p in parts.SkipLast(1))
                    {
                        sb.Append(CultureInfo.InvariantCulture, $"notEmpty({p}), {p}, ");
                    }
                    sb.Append(parts[^1]).Append(')');
                    return new SqlExpr(sb.ToString(), SqlType.String);
                case "isnull":
                    Arity(1, 1);
                    return new SqlExpr($"NOT ({Present(Arg(0))})", SqlType.Bool);
                case "isnotnull":
                    Arity(1, 1);
                    return new SqlExpr(Present(Arg(0)), SqlType.Bool);
                case "like":
                    Arity(2, 2);
                    return new SqlExpr($"(toString({Arg(0).Sql}) LIKE {Arg(1).Sql})", SqlType.Bool);
                case "match":
                    Arity(2, 2);
                    return new SqlExpr($"match(toString({Arg(0).Sql}), {Arg(1).Sql})", SqlType.Bool);
                case "cidrmatch":
                    Arity(2, 2);
                    return new SqlExpr(CidrMatch(Arg(1), Arg(0).Sql), SqlType.Bool);
                case "now":
                    Arity(0, 0);
                    return new SqlExpr("now64(3)", SqlType.DateTime);
                case "relative_time" or "ago":
                    Arity(1, 1);
                    if (call.Args[0] is not Literal { Value: string spanText })
                    {
                        throw new QueryParseException("ago() takes a span like \"15m\".", call.Position);
                    }
                    var span = PipeParser.ParseSpan(new Token(TokenKind.Word, spanText, call.Position));
                    return new SqlExpr($"(now64(3) - {Interval(span)})", SqlType.DateTime);
                default:
                    throw new QueryParseException(
                        $"Unknown function '{call.Function}'. Available: lower, upper, len, tostring, tonumber, round, abs, substr, replace, if, coalesce, isnull, isnotnull, like, match, cidrmatch, now, ago.",
                        call.Position);
            }
        }

        // ------------------------------------------------------------ helpers

        private SqlExpr Resolve(string name, int position)
        {
            var canonical = FieldCatalog.Canonical(name);
            if (_stage.Fields.TryGetValue(canonical, out var computed) || _stage.Fields.TryGetValue(name, out computed))
            {
                return computed;
            }
            if (!FieldCatalog.IsValidName(canonical))
            {
                throw new QueryParseException($"'{name}' is not a valid field name.", position);
            }
            if (_stage.EventMode)
            {
                return FieldCatalog.Resolve(canonical, Param);
            }
            throw new QueryParseException(
                $"Field '{name}' doesn't exist at this point. Available: {string.Join(", ", _stage.FieldOrder)}.", position);
        }

        private string OrderTarget(string field, int position)
        {
            var name = OutputName(field);
            // Prefer a column of the current select (aliases), else the underlying field.
            if (_stage.Select is { } select && select.Any(s => s.Alias == name))
            {
                return Quote(name);
            }
            return Resolve(field, position).Sql;
        }

        private IEnumerable<string> CurrentColumns() =>
            _stage.Select?.Select(s => s.Alias) ??
            (_stage.EventMode ? FieldCatalog.DefaultEventColumns.Concat(_stage.FieldOrder.Where(f => !FieldCatalog.DefaultEventColumns.Contains(f))) : _stage.FieldOrder);

        private (string Sql, List<string> Columns) Render(Stage stage)
        {
            List<(string Alias, SqlExpr Expr)> select;
            if (stage.Select is not null)
            {
                select = stage.Select;
            }
            else if (stage.EventMode)
            {
                select = CurrentColumns().Select(c => (c, stage.Fields.GetValueOrDefault(c) ?? FieldCatalog.Resolve(c, Param))).ToList();
            }
            else
            {
                select = stage.FieldOrder.Select(f => (f, stage.Fields[f])).ToList();
            }

            var sb = new StringBuilder("SELECT ");
            sb.AppendJoin(", ", select.Select(s => $"{s.Expr.Sql} AS {Quote(s.Alias)}"));
            sb.Append(" FROM ").Append(stage.Source ?? $"{database}.events");
            if (stage.ArrayJoin is not null)
            {
                sb.Append(" ARRAY JOIN ").Append(stage.ArrayJoin);
            }
            if (stage.Where.Count > 0)
            {
                sb.Append(" WHERE ").AppendJoin(" AND ", stage.Where.Select(w => $"({w})"));
            }
            if (stage.GroupBy.Count > 0)
            {
                sb.Append(" GROUP BY ").AppendJoin(", ", stage.GroupBy);
            }
            if (stage.OrderBy.Count > 0)
            {
                sb.Append(" ORDER BY ").AppendJoin(", ", stage.OrderBy);
            }
            if (stage.LimitBy.Count > 0)
            {
                sb.Append(CultureInfo.InvariantCulture, $" LIMIT {stage.LimitByCount ?? 1} BY ").AppendJoin(", ", stage.LimitBy);
            }
            if (stage.Limit is { } limit)
            {
                sb.Append(CultureInfo.InvariantCulture, $" LIMIT {limit}");
            }
            return (sb.ToString(), select.Select(s => s.Alias).ToList());
        }

        private Dictionary<string, SqlType> OutputTypes(Stage stage)
        {
            if (stage.Select is not null)
            {
                return stage.Select.ToDictionary(s => s.Alias, s => s.Expr.Type, StringComparer.Ordinal);
            }
            return CurrentColumns().ToDictionary(c => c, c => (stage.Fields.GetValueOrDefault(c) ?? FieldCatalog.Resolve(c, Param)).Type, StringComparer.Ordinal);
        }

        private string Param(object value, string type)
        {
            var name = "p" + _params.Count.ToString(CultureInfo.InvariantCulture);
            _params[name] = value;
            _paramTypes[name] = type;
            return $"{{{name}:{type}}}";
        }

        private static string OutputName(string field) => FieldCatalog.Canonical(field);

        private static string OutputName(Aggregation agg) =>
            agg.Field is null ? agg.Function : $"{agg.Function}({FieldCatalog.Canonical(agg.Field)})";

        /// <summary>
        /// Output names (aliases, rex groups, eval fields) become backtick-quoted SQL identifiers. Quote escapes them,
        /// and as a second guard names can't contain quotes, backslashes or control characters at all.
        /// </summary>
        private static string ValidName(string name, int position) =>
            name.Length is 0 or > 128 || name.Any(c => c is '`' or '\\' or '"' or '\'' || char.IsControl(c))
                ? throw new QueryParseException($"'{name}' is not a valid output name: quotes and backslashes aren't allowed.", position)
                : name;

        /// <summary>A backtick-quoted identifier. Backslash and backtick are escapes inside one, so both are escaped.</summary>
        private static string Quote(string name) =>
            "`" + name.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("`", "\\`", StringComparison.Ordinal) + "`";

        private static string Bool(SqlExpr expr) => expr.Type switch
        {
            SqlType.Bool => expr.Sql,
            SqlType.Number => $"({expr.Sql} != 0)",
            _ => Present(expr),
        };

        /// <summary>"Has a value": events store missing strings as '' and missing ports as 0.</summary>
        private static string Present(SqlExpr expr) => expr.Type switch
        {
            SqlType.Number => $"({expr.Sql} != 0)",
            SqlType.Array => $"notEmpty({expr.Sql})",
            SqlType.Bool => expr.Sql,
            _ => $"notEmpty(toString({expr.Sql}))",
        };

        private static string ToNumber(SqlExpr expr) => expr.Type switch
        {
            SqlType.Number => expr.Sql,
            SqlType.Bool => $"toFloat64({expr.Sql})",
            SqlType.DateTime => $"toFloat64(toUnixTimestamp64Milli({expr.Sql}))",
            _ => $"toFloat64OrNull(toString({expr.Sql}))",
        };

        private static string CidrMatch(SqlExpr address, string cidrSql)
        {
            var a = $"toString({address.Sql})";
            return $"if(isIPv4String({a}) OR isIPv6String({a}), isIPAddressInRange({a}, {cidrSql}), 0)";
        }

        /// <summary>Wildcard text → LIKE pattern: <c>*</c> becomes <c>%</c>; literal <c>%</c>, <c>_</c> and <c>\</c> are escaped.</summary>
        private static string LikePattern(string wildcard)
        {
            var sb = new StringBuilder(wildcard.Length + 4);
            foreach (var c in wildcard)
            {
                sb.Append(c switch
                {
                    '*' => "%",
                    '%' => "\\%",
                    '_' => "\\_",
                    '\\' => "\\\\",
                    _ => c.ToString(),
                });
            }
            return sb.ToString();
        }

        private TimeSpan AutoSpan(TimeSpan range)
        {
            TimeSpan[] steps =
            [
                TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(15),
                TimeSpan.FromMinutes(30), TimeSpan.FromHours(1), TimeSpan.FromHours(3), TimeSpan.FromHours(6),
                TimeSpan.FromHours(12), TimeSpan.FromDays(1), TimeSpan.FromDays(7),
            ];
            return steps.FirstOrDefault(s => range / s <= options.TimechartBuckets, steps[^1]);
        }

        private static string Interval(TimeSpan span)
        {
            var seconds = (long)span.TotalSeconds;
            var (value, unit) = seconds switch
            {
                _ when seconds % 604800 == 0 => (seconds / 604800, "WEEK"),
                _ when seconds % 86400 == 0 => (seconds / 86400, "DAY"),
                _ when seconds % 3600 == 0 => (seconds / 3600, "HOUR"),
                _ when seconds % 60 == 0 => (seconds / 60, "MINUTE"),
                _ => (seconds, "SECOND"),
            };
            return $"INTERVAL {value.ToString(CultureInfo.InvariantCulture)} {unit}";
        }
    }
}

/// <summary>Converts a rex pattern with named groups to RE2 with plain groups, recording each name's group index.</summary>
internal static class RexPattern
{
    public static (string Pattern, List<(string Name, int Index)> Groups) Convert(string pattern, int position)
    {
        var sb = new StringBuilder(pattern.Length);
        var groups = new List<(string, int)>();
        var index = 0;
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                sb.Append(c).Append(pattern[++i]);
                continue;
            }
            if (inClass)
            {
                inClass = c != ']';
                sb.Append(c);
                continue;
            }
            if (c == '[')
            {
                inClass = true;
                sb.Append(c);
                continue;
            }
            if (c != '(')
            {
                sb.Append(c);
                continue;
            }

            // (?<name>  or  (?P<name>
            var nameStart = pattern.AsSpan(i).StartsWith("(?<") && i + 3 < pattern.Length && pattern[i + 3] is not ('=' or '!') ? i + 3
                : pattern.AsSpan(i).StartsWith("(?P<") ? i + 4 : -1;
            if (nameStart > 0)
            {
                var close = pattern.IndexOf('>', nameStart);
                if (close < 0)
                {
                    throw new QueryParseException("Unterminated group name in rex pattern.", position);
                }
                index++;
                groups.Add((pattern[nameStart..close], index));
                sb.Append('(');
                i = close;
                continue;
            }
            if (i + 1 < pattern.Length && pattern[i + 1] == '?')
            {
                sb.Append(c); // non-capturing or flags: (?: (?i) ...
                continue;
            }
            index++; // unnamed capturing group still takes a slot
            sb.Append(c);
        }
        if (groups.Count == 0)
        {
            throw new QueryParseException("rex needs at least one named group, e.g. (?<user>\\w+).", position);
        }
        return (sb.ToString(), groups);
    }
}
