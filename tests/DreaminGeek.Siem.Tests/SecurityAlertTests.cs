using Cronos;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Alerts;

namespace DreaminGeek.Siem.Tests;

public sealed class SecurityAlertTests
{
    public static TheoryData<string> Names() => new(SecurityAlerts.All.Select(t => t.Name));

    [Theory]
    [MemberData(nameof(Names))]
    public void Template_is_a_working_alert(string name)
    {
        var t = SecurityAlerts.All.Single(x => x.Name == name);
        Assert.True(AlertEvaluator.ParseLookback(t.TimeRange) > TimeSpan.Zero);
        Assert.NotNull(CronExpression.Parse(t.Schedule).GetNextOccurrence(DateTime.UtcNow));
        if (t.Kind != AlertRuleKind.Search)
        {
            // Health checks have no search, and one alert per tenant lists everything wrong.
            Assert.Equal(string.Empty, t.Query);
            Assert.Equal(AlertTrigger.Once, t.Trigger);
            Assert.Equal(SecurityAlerts.Health, t.Group);
            Assert.Equal(t.Kind, SecurityAlerts.ToForm(t, null).Kind);
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var compiled = new ClickHouseCompiler("dgsiem").Compile(new PipeParser().Parse(t.Query),
            new QueryRequest(t.Query, now.AddHours(-1), now, ["dg"]));
        Assert.Contains("tenant_id IN", compiled.Sql, StringComparison.Ordinal);

        // Repeats are recognised by these fields, so they must be columns of the result.
        foreach (var key in (t.SuppressBy ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            Assert.Contains(key, compiled.Columns);
        }

        var form = SecurityAlerts.ToForm(t, "jdoe@example.com");
        Assert.Equal(t.Severity >= AlertSeverity.High, form.CreateTicket);
        Assert.Equal(string.Empty, form.Tenant); // each tenant separately
        Assert.Equal("jdoe@example.com", form.EmailTo);
        Assert.True(form.Enabled);
    }

    [Fact]
    public void Names_are_unique_and_every_group_is_covered()
    {
        Assert.Equal(SecurityAlerts.All.Count, SecurityAlerts.All.Select(t => t.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal([SecurityAlerts.ThreatIntel, SecurityAlerts.Health, SecurityAlerts.Windows, SecurityAlerts.Defender, SecurityAlerts.Pbx, SecurityAlerts.Identity], SecurityAlerts.All.Select(t => t.Group).Distinct());
        Assert.Null(SecurityAlerts.ToForm(SecurityAlerts.All[0], " ").EmailTo);
    }
}
