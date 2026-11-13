using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Search;
using DreaminGeek.Siem.Web.Security;

namespace DreaminGeek.Siem.Tests;

public class SearchUiTests
{
    [Theory]
    [InlineData("", "host.name", "AP-01", false, "host.name=\"AP-01\"")]
    [InlineData("*", "host.name", "AP-01", false, "host.name=\"AP-01\"")]
    [InlineData("dataset=unifi.firewall", "source.ip", "203.0.113.9", false, "dataset=unifi.firewall source.ip=\"203.0.113.9\"")]
    [InlineData("dataset=unifi.* | top src", "host.name", "UDM-Office", true, "dataset=unifi.* NOT host.name=\"UDM-Office\" | top src")]
    [InlineData("\"a | b\" | head 5", "x", "y", false, "\"a | b\" x=\"y\" | head 5")]
    public void Click_to_filter_edits_only_the_search_clause(string query, string field, string value, bool exclude, string expected) =>
        Assert.Equal(expected, SearchService.AddFilter(query, field, value, exclude));

    [Fact]
    public void Quoted_values_survive_the_parser()
    {
        const string nasty = "say \"hi\" \\ there | not a pipe";
        var query = SearchService.AddFilter("", "message", nasty, false);
        var parsed = new PipeParser().Parse(query);
        Assert.Empty(parsed.Commands);
        var comparison = Assert.IsType<BinaryExpr>(parsed.Search.Filter);
        Assert.Equal(nasty, Assert.IsType<QuotedValue>(Assert.IsType<Literal>(comparison.Right).Value).Text);
    }

    [Fact]
    public void Tenant_narrowing_never_widens_access()
    {
        var access = new UserAccess(Guid.NewGuid(), false, ["acme"]);
        Assert.Equal(["acme"], TenantAccess.Narrow(access, null));
        Assert.Equal(["acme"], TenantAccess.Narrow(access, []));
        Assert.Equal(["acme"], TenantAccess.Narrow(access, ["acme", "globex"]));
        Assert.Empty(TenantAccess.Narrow(access, ["globex"]));
    }

    [Fact]
    public void Fieldsummary_parses_with_defaults_and_options()
    {
        var parser = new PipeParser();
        var d = Assert.IsType<FieldSummaryCommand>(parser.Parse("* | fieldsummary").Commands[0]);
        Assert.Empty(d.Fields);
        Assert.Equal(5, d.MaxValues);
        var c = Assert.IsType<FieldSummaryCommand>(parser.Parse("* | fieldsummary maxvals=3 host, src").Commands[0]);
        Assert.Equal(["host", "src"], c.Fields);
        Assert.Equal(3, c.MaxValues);
    }

    [Fact]
    public void Fieldsummary_compiles_to_one_array_join_pass()
    {
        var q = ClickHouseCompilerTests.Compile("dataset=unifi.firewall | fieldsummary maxvals=3 src, dport");
        Assert.Equal(["field", "value", "count"], q.Columns);
        Assert.Contains("ARRAY JOIN [tuple({p", q.Sql, StringComparison.Ordinal);
        Assert.Contains("LIMIT 3 BY _kv.1", q.Sql, StringComparison.Ordinal);
        Assert.Contains("(destination_port != 0)", q.Sql, StringComparison.Ordinal); // missing ports are skipped
    }
}
