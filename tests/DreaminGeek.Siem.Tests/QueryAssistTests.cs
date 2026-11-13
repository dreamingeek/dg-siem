using DreaminGeek.Siem.Query;

namespace DreaminGeek.Siem.Tests;

public class QueryAssistTests
{
    /// <summary>Analyzes the query with the cursor where the ^ marker is.</summary>
    private static AssistContext At(string withCaret)
    {
        var cursor = withCaret.IndexOf('^', StringComparison.Ordinal);
        return QueryAssist.Analyze(withCaret.Remove(cursor, 1), cursor);
    }

    [Theory]
    [InlineData("^", AssistKind.Field, "")]
    [InlineData("data^", AssistKind.Field, "data")]
    [InlineData("dataset=unifi.firewall so^", AssistKind.Field, "so")]
    [InlineData("NOT ho^", AssistKind.Field, "ho")]
    public void Search_clause_suggests_fields(string query, AssistKind kind, string prefix)
    {
        var c = At(query);
        Assert.Equal(kind, c.Kind);
        Assert.Equal(prefix, c.Prefix);
        Assert.True(c.InSearchClause);
    }

    [Theory]
    [InlineData("dataset=^", "dataset", "")]
    [InlineData("dataset=unifi.f^", "dataset", "unifi.f")]
    [InlineData("x src!=10.0^", "src", "10.0")]
    [InlineData("dport>=10^", "dport", "10")]
    public void Search_clause_suggests_values_after_operators(string query, string field, string prefix)
    {
        var c = At(query);
        Assert.Equal(AssistKind.Value, c.Kind);
        Assert.Equal(field, c.Field);
        Assert.Equal(prefix, c.Prefix);
    }

    [Fact]
    public void Quoted_value_in_progress_replaces_the_whole_quoted_token()
    {
        var c = At("user=\"Jane D^\" | top src");
        Assert.Equal(AssistKind.Value, c.Kind);
        Assert.Equal("user", c.Field);
        Assert.Equal("Jane D", c.Prefix);
        Assert.Equal(5, c.ReplaceStart);   // the opening quote
        Assert.Equal(13, c.ReplaceEnd);    // just past the closing quote
    }

    [Theory]
    [InlineData("* |^")]
    [InlineData("* | ^")]
    [InlineData("* | st^")]
    [InlineData("* | stats count | to^")]
    public void After_a_pipe_suggests_commands(string query) => Assert.Equal(AssistKind.Command, At(query).Kind);

    [Theory]
    [InlineData("* | stats ^", AssistKind.Aggregation)]
    [InlineData("* | stats count(), d^", AssistKind.Aggregation)]
    [InlineData("* | stats dc(^", AssistKind.Field)]
    [InlineData("* | stats count by ^", AssistKind.Field)]
    [InlineData("* | stats count by host, ^", AssistKind.Field)]
    [InlineData("* | stats count as ^", AssistKind.None)]
    [InlineData("* | timechart span=1h ^", AssistKind.Aggregation)]
    [InlineData("* | top ^", AssistKind.Field)]
    [InlineData("* | table @timestamp, so^", AssistKind.Field)]
    [InlineData("* | sort -co^", AssistKind.Field)]
    [InlineData("* | where ^", AssistKind.Expression)]
    [InlineData("* | eval ^", AssistKind.None)]
    [InlineData("* | eval kb = ^", AssistKind.Expression)]
    [InlineData("* | head ^", AssistKind.None)]
    [InlineData("* | rex field=^", AssistKind.Field)]
    [InlineData("* | rex \"(?<x>^", AssistKind.None)]
    public void Commands_know_what_comes_next(string query, AssistKind kind) => Assert.Equal(kind, At(query).Kind);

    [Fact]
    public void Where_values_must_be_quoted()
    {
        var c = At("* | where action=bl^");
        Assert.Equal(AssistKind.Value, c.Kind);
        Assert.Equal("action", c.Field);
        Assert.True(c.QuoteValues);
    }

    [Fact]
    public void Sort_direction_prefix_is_kept()
    {
        var c = At("* | stats count by src | sort -co^");
        Assert.Equal("co", c.Prefix);
        Assert.Equal("* | stats count by src | sort -".Length, c.ReplaceStart);
    }

    [Fact]
    public void Editing_mid_token_replaces_the_whole_token()
    {
        var c = At("data^set=x");
        Assert.Equal(0, c.ReplaceStart);
        Assert.Equal("dataset".Length, c.ReplaceEnd);
    }

    [Fact]
    public void Hints_follow_the_current_command()
    {
        Assert.Equal(QueryAssist.SearchHint, At("dat^").Hint);
        Assert.StartsWith("stats <agg>", At("* | stats count by ^").Hint, StringComparison.Ordinal);
        Assert.StartsWith("timechart", At("* | stats count | timechart ^").Hint, StringComparison.Ordinal);
    }

    [Fact]
    public void BuiltInFieldsListUsefulOnesFirst()
    {
        var names = QueryAssist.BuiltInFields.Select(f => f.Name).ToList();
        Assert.Contains("message", names);
        Assert.True(names.IndexOf("host.name") < names.IndexOf("@timestamp"));
        Assert.True(names.IndexOf("event.dataset") < names.IndexOf("event.id"));
        Assert.DoesNotContain("_fields", names);
    }
}
