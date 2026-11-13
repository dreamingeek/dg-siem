using DreaminGeek.Siem.Query;

namespace DreaminGeek.Siem.Tests;

public class PipeParserTests
{
    private readonly PipeParser _parser = new();

    [Fact]
    public void Empty_or_star_search_means_everything()
    {
        Assert.Null(_parser.Parse("").Search.Filter);
        Assert.Null(_parser.Parse("   *  ").Search.Filter);
    }

    [Fact]
    public void Search_clause_with_fields_terms_boolean_and_barewords()
    {
        var p = _parser.Parse("dataset=unifi.firewall src=10.0.0.5 NOT action=accept (ssh OR \"failed password\") host=AP-*");
        var f = Assert.IsType<BinaryExpr>(p.Search.Filter);
        Assert.Equal("AND", f.Op);
        var text = Flatten(p.Search.Filter!);
        Assert.Contains("dataset=unifi.firewall", text, StringComparison.Ordinal);
        Assert.Contains("src=10.0.0.5", text, StringComparison.Ordinal);
        Assert.Contains("NOT(action=accept)", text, StringComparison.Ordinal);
        Assert.Contains("OR", text, StringComparison.Ordinal);
        Assert.Contains("term:ssh", text, StringComparison.Ordinal);
        Assert.Contains("\"failed password\"", text, StringComparison.Ordinal);
        Assert.Contains("host=AP-*", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Pipes_inside_quotes_are_not_command_separators()
    {
        var p = _parser.Parse("\"a | b\" | head 5");
        Assert.Single(p.Commands);
        Assert.Equal("term:\"a | b\"", Flatten(p.Search.Filter!));
    }

    [Fact]
    public void Parses_every_command()
    {
        var p = _parser.Parse(
            "* | where source.port > 1024 AND NOT user.name IN (\"root\", \"admin\") " +
            "| eval kb = network.bytes / 1024, label = host.name . \"-\" . lower(event.action) " +
            "| rex field=message \"user=(?<user>\\w+)\" " +
            "| stats count() as hits, dc(source.ip), p95(kb) by host.name, event.dataset " +
            "| sort -hits, +host.name | head 20 | dedup host.name | table host.name, hits | fields - hits");

        Assert.Collection(p.Commands,
            c => Assert.IsType<WhereCommand>(c),
            c => Assert.Equal(2, Assert.IsType<EvalCommand>(c).Assignments.Count),
            c => Assert.Equal("user=(?<user>\\w+)", Assert.IsType<RexCommand>(c).Pattern),
            c =>
            {
                var stats = Assert.IsType<StatsCommand>(c);
                Assert.Equal(["hits", "dc(source.ip)", "p95(kb)"], stats.Aggregations.Select(a => a.OutputName));
                Assert.Equal(["host.name", "event.dataset"], stats.By);
            },
            c => Assert.Equal([new SortKey("hits", true), new SortKey("host.name", false)], Assert.IsType<SortCommand>(c).Keys),
            c => Assert.Equal(20, Assert.IsType<HeadCommand>(c).Count),
            c => Assert.IsType<DedupCommand>(c),
            c => Assert.IsType<TableCommand>(c),
            c => Assert.True(Assert.IsType<FieldsCommand>(c).Exclude));
    }

    [Fact]
    public void Timechart_and_top_options()
    {
        var chart = Assert.IsType<TimechartCommand>(_parser.Parse("| timechart span=15m count by event.dataset").Commands[0]);
        Assert.Equal(TimeSpan.FromMinutes(15), chart.Span);
        Assert.Equal("event.dataset", chart.By);

        var top = Assert.IsType<TopCommand>(_parser.Parse("| top limit=5 source.ip by host.name").Commands[0]);
        Assert.Equal(("source.ip", "host.name", 5), (top.Field, top.By, top.Limit));
    }

    [Theory]
    [InlineData("| bogus", 2, "Unknown command 'bogus'")]
    [InlineData("x | where (a = 1", 16, "Expected ')'")]
    [InlineData("\"unterminated", 0, "Unterminated")]
    [InlineData("| stats by host", 8, "at least one aggregation")]
    [InlineData("| head 0", 7, "positive whole number")]
    [InlineData("| timechart span=5x count", 17, "Invalid span")]
    [InlineData("a | ", 4, "Empty command")]
    public void Errors_point_at_the_problem(string query, int position, string message)
    {
        var ex = Assert.Throws<QueryParseException>(() => _parser.Parse(query));
        Assert.Contains(message, ex.Message, StringComparison.Ordinal);
        Assert.Equal(position, ex.Position);
    }

    private static string Flatten(Expr e) => e switch
    {
        BinaryExpr { Op: "AND" or "OR" } b => $"({Flatten(b.Left)} {b.Op} {Flatten(b.Right)})",
        BinaryExpr b => $"{Flatten(b.Left)}{b.Op}{Flatten(b.Right)}",
        NotExpr n => $"NOT({Flatten(n.Operand)})",
        FieldRef f => f.Name,
        Literal { Value: QuotedValue q } => $"\"{q.Text}\"",
        Literal l => l.Value.ToString()!,
        TermExpr t => t.Quoted ? $"term:\"{t.Text}\"" : $"term:{t.Text}",
        _ => e.GetType().Name,
    };
}

public class ClickHouseCompilerTests
{
    /// <summary>
    /// Security review finding: a backslash at the end of a backtick-quoted output name escaped the closing backtick,
    /// so the next name's text ran as SQL and could comment out the tenant filter.
    /// </summary>
    [Theory]
    [InlineData("""* | stats count as "a\\", count as ", tenant_id AS t FROM dgsiem.events GROUP BY t -- " """)]
    [InlineData("""* | rex field=message "(?<a\\>x)" | table a""")]
    [InlineData("""* | stats count as "x`y" """)]
    [InlineData("""* | eval "a'b"=1""")]
    public void Output_names_cannot_break_out_of_their_quotes(string query) =>
        Assert.ThrowsAny<QueryParseException>(() => Compile(query.Trim()));

    [Fact]
    public void Ordinary_output_names_still_work()
    {
        var compiled = Compile("""* | stats count as "events/min", dc(source.ip) as "unique sources (24 h)" by host""");
        Assert.Contains("AS `events/min`", compiled.Sql, StringComparison.Ordinal);
        Assert.Contains("AS `unique sources (24 h)`", compiled.Sql, StringComparison.Ordinal);
        Assert.Contains("tenant_id IN", compiled.Sql, StringComparison.Ordinal);
    }

    private static readonly DateTimeOffset From = new(2026, 11, 11, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset To = new(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);

    internal static CompiledQuery Compile(string query, params string[] tenants) =>
        new ClickHouseCompiler("dgsiem").Compile(new PipeParser().Parse(query),
            new QueryRequest(query, From, To, tenants.Length == 0 ? ["dg"] : tenants));

    [Fact]
    public void Always_scoped_to_tenants_and_time_range()
    {
        var q = Compile("anything", "dg", "acme");
        Assert.StartsWith("SELECT ", q.Sql, StringComparison.Ordinal);
        Assert.Contains("FROM dgsiem.events WHERE (tenant_id IN {p0:Array(String)}) AND (timestamp >= {p1:DateTime64(3, 'UTC')}) AND (timestamp < {p2:DateTime64(3, 'UTC')})", q.Sql, StringComparison.Ordinal);
        Assert.Equal(new[] { "dg", "acme" }, (string[])q.Parameters["p0"]);
        Assert.Equal(From.UtcDateTime, q.Parameters["p1"]);
    }

    [Fact]
    public void Tenant_scoping_survives_subqueries()
    {
        var q = Compile("* | stats count() by host | where count > 5 | eval x = count * 2 | sort -x");
        // The tenant filter sits on the innermost (only) read of the events table.
        Assert.Equal(1, Occurrences(q.Sql, "FROM dgsiem.events"));
        Assert.Contains("tenant_id IN {p0:Array(String)}", q.Sql, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("'; DROP TABLE dgsiem.events; --")]
    [InlineData("x\") OR 1=1 --")]
    [InlineData("`backtick` injection")]
    public void User_values_never_appear_in_sql(string evil)
    {
        var escaped = evil.Replace("\"", "\\\"", StringComparison.Ordinal);
        var q = Compile($"\"{escaped}\" user.name=\"{escaped}\" | where match(message, \"{escaped}\") | eval z = \"{escaped}\"");
        Assert.DoesNotContain("DROP", q.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("1=1", q.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("backtick", q.Sql, StringComparison.Ordinal);
        Assert.Contains(evil, q.Parameters.Values.OfType<string>());
    }

    [Theory]
    [InlineData("eval `x` = 1")]
    [InlineData("table \"a`b\"")]
    public void Backticks_in_names_are_rejected(string command) =>
        Assert.Throws<QueryParseException>(() => Compile("* | " + command));

    [Fact]
    public void Field_comparisons_by_type()
    {
        var q = Compile("src=10.0.0.0/8 dport>1024 host=AP-* user=\"jdoe\" dataset=unifi.firewall custom.thing=abc");
        Assert.Contains("isIPAddressInRange(toString(source_ip), {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("destination_port > {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("toString(host_name) ILIKE {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("toString(user_name) = {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("toString(event_dataset) = {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("fields[{p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("AP-%", q.Parameters.Values.OfType<string>());
        Assert.Contains(1024.0, q.Parameters.Values.OfType<double>());
        Assert.Contains("custom.thing", q.Parameters.Values.OfType<string>()); // map key is a parameter too
    }

    [Fact]
    public void Search_terms_use_token_search_for_words_and_substring_for_phrases()
    {
        var q = Compile("ssh \"failed password\" fail*");
        Assert.Contains("hasTokenCaseInsensitive(raw, {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("positionCaseInsensitiveUTF8(raw, {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("raw ILIKE {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("%fail%", q.Parameters.Values.OfType<string>());
    }

    [Fact]
    public void Underscored_words_are_not_single_tokens()
    {
        // ClickHouse treats '_' as a token separator; hasToken would throw on "quick_mode".
        var q = Compile("quick_mode");
        Assert.DoesNotContain("hasToken", q.Sql, StringComparison.Ordinal);
        Assert.Contains("positionCaseInsensitiveUTF8(raw, {p", q.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Raw_event_search_defaults()
    {
        var q = Compile("ssh");
        Assert.Equal(ResultShape.Events, q.Shape);
        Assert.Equal(["@timestamp", "tenant", "host.name", "event.dataset", "log.level", "message", "event.id"], q.Columns);
        Assert.EndsWith("ORDER BY timestamp DESC LIMIT 1000", q.Sql, StringComparison.Ordinal);
        Assert.Equal(1000, q.RowLimit);
    }

    [Fact]
    public void Eval_fields_are_added_to_event_results_and_inlined_in_filters()
    {
        var q = Compile("* | eval kb = network.bytes / 1024 | where kb > 10");
        Assert.Contains("kb", q.Columns);
        Assert.Contains("(toFloat64OrNull(toString(fields[{p", q.Sql, StringComparison.Ordinal);
        Assert.Equal(1, Occurrences(q.Sql, "SELECT ")); // no subquery needed
    }

    [Fact]
    public void Stats_groups_by_expressions_and_orders_by_group_keys()
    {
        var q = Compile("dataset=unifi.firewall | stats count() as hits, dc(src) by host");
        Assert.Equal(ResultShape.Table, q.Shape);
        Assert.Equal(["host.name", "hits", "dc(source.ip)"], q.Columns);
        Assert.Contains("count() AS `hits`", q.Sql, StringComparison.Ordinal);
        Assert.Contains("uniqExactIf(source_ip, notEmpty(toString(source_ip))) AS `dc(source.ip)`", q.Sql, StringComparison.Ordinal);
        Assert.Contains("GROUP BY host_name ORDER BY host_name ASC LIMIT 10000", q.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Where_after_stats_wraps_in_a_subquery()
    {
        var q = Compile("* | stats count() by src | where count > 100 | sort -count | head 5");
        Assert.Matches(@"^SELECT `source\.ip` AS `source\.ip`, `count` AS `count` FROM \(SELECT .* GROUP BY source_ip\) WHERE \(\(`count` > \{p\d+:Float64\}\)\) ORDER BY `count` DESC LIMIT 5$", q.Sql);
    }

    [Fact]
    public void Top_counts_with_percent_and_limit()
    {
        var q = Compile("dataset=unifi.firewall | top limit=3 src");
        Assert.Equal(["source.ip", "count", "percent"], q.Columns);
        Assert.Contains("sum(count()) OVER ()", q.Sql, StringComparison.Ordinal);
        Assert.EndsWith("ORDER BY `count` DESC LIMIT 3", q.Sql, StringComparison.Ordinal);

        var byHost = Compile("* | top src by host");
        Assert.Contains("LIMIT 10 BY host_name", byHost.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Timechart_auto_span_for_a_day_is_15_minutes()
    {
        var q = Compile("* | timechart count by dataset");
        Assert.Equal(ResultShape.Timechart, q.Shape);
        Assert.Contains("toStartOfInterval(timestamp, INTERVAL 15 MINUTE) AS `_time`", q.Sql, StringComparison.Ordinal);
        Assert.Contains("ORDER BY `_time` ASC, `event.dataset` ASC", q.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Rex_maps_named_groups_to_extract_group_indexes()
    {
        var q = Compile("* | rex \"(\\d+)\\[(?<sub>[A-Z]{3})\\] (?:parsed|generating) (?P<kind>\\w+)\" | stats count by sub, kind");
        Assert.Contains(@"(\d+)\[([A-Z]{3})\] (?:parsed|generating) (\w+)", q.Parameters.Values.OfType<string>());
        Assert.Contains("arrayElement(extractGroups(toString(message), {p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("), 2) AS `sub`", q.Sql, StringComparison.Ordinal);
        Assert.Contains("), 3) AS `kind`", q.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Dedup_uses_limit_by_and_head_caps_rows()
    {
        var q = Compile("* | dedup host | head 50000");
        Assert.Contains("LIMIT 1 BY host_name LIMIT 10000", q.Sql, StringComparison.Ordinal); // capped at MaxRows
    }

    [Theory]
    [InlineData("* | stats nope(x)", "Unknown aggregation")]
    [InlineData("* | where foo(x)", "Unknown function")]
    [InlineData("* | stats count by host | table src", "doesn't exist at this point")]
    [InlineData("* | stats count | timechart count", "timechart needs raw events")]
    [InlineData("* | rex \"no groups\"", "named group")]
    public void Semantic_errors(string query, string message)
    {
        var ex = Assert.Throws<QueryParseException>(() => Compile(query));
        Assert.Contains(message, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void No_tenants_means_no_query()
    {
        var ex = Assert.Throws<QueryParseException>(() =>
            new ClickHouseCompiler("dgsiem").Compile(new PipeParser().Parse("*"), new QueryRequest("*", From, To, [])));
        Assert.Contains("access", ex.Message, StringComparison.Ordinal);
    }

    private static int Occurrences(string text, string value)
    {
        var count = 0;
        for (var i = text.IndexOf(value, StringComparison.Ordinal); i >= 0; i = text.IndexOf(value, i + 1, StringComparison.Ordinal))
        {
            count++;
        }
        return count;
    }

    [Fact]
    public void Field_star_means_has_a_value()
    {
        var present = Compile("src=* user!=* dport=*");
        Assert.Contains("toString(source_ip) != ''", present.Sql, StringComparison.Ordinal);
        Assert.Contains("NOT (toString(user_name) != '')", present.Sql, StringComparison.Ordinal);
        Assert.Contains("destination_port != 0", present.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("ILIKE", present.Sql, StringComparison.Ordinal);

        // Other wildcards still match as patterns.
        Assert.Contains("ILIKE", Compile("host=AP-*").Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Threat_shortcuts_search_the_enrichment_fields()
    {
        // Map keys go in as parameters, never into the SQL text.
        var anyMatch = Compile("threat_feed=* | stats count() by threat_feed, threat_on");
        Assert.Contains("fields[{", anyMatch.Sql, StringComparison.Ordinal);
        Assert.Contains("!= ''", anyMatch.Sql, StringComparison.Ordinal);
        Assert.Contains("threat.feed.name", anyMatch.Parameters.Values.OfType<string>());
        Assert.Contains("threat.enrichments.matched.field", anyMatch.Parameters.Values.OfType<string>());
        Assert.Equal(["threat.feed.name", "threat.enrichments.matched.field", "count"], anyMatch.Columns);

        var outbound = Compile("threat_on=destination.ip");
        Assert.Contains("threat.enrichments.matched.field", outbound.Parameters.Values.OfType<string>());
        Assert.Contains("destination.ip", outbound.Parameters.Values.OfType<string>());
        Assert.Contains("tenant_id IN", outbound.Sql, StringComparison.Ordinal);
    }
}
