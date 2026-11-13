using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Ingest;

namespace DreaminGeek.Siem.Tests;

public class DropFilterTests
{
    private sealed class FixedRules(params DropRule[] rules) : IDropRuleSource
    {
        public IReadOnlyList<DropRule> Current => rules;
        public Dictionary<Guid, long> Reported { get; } = [];

        public void Report(IReadOnlyDictionary<Guid, long> droppedByRule)
        {
            foreach (var (id, n) in droppedByRule)
            {
                Reported[id] = Reported.GetValueOrDefault(id) + n;
            }
        }
    }

    private static LogEvent Event(string tenant, string dataset, string action = "", string message = "") =>
        new() { TenantId = tenant, Timestamp = DateTimeOffset.UtcNow, EventDataset = dataset, EventAction = action, Message = message, Raw = message };

    private static readonly DropRule Keepalives = new(Guid.NewGuid(), "IPsec keepalives", null, "unifi.vpn", "event.action", DropMatch.Equals, "ipsec_keepalive");

    [Fact]
    public void Drops_matching_events_and_counts_them()
    {
        var rules = new FixedRules(Keepalives);
        var filter = new DropFilter(rules);

        Assert.Same(Keepalives, filter.Match(Event("dg", "unifi.vpn", "ipsec_keepalive")));
        Assert.Same(Keepalives, filter.Match(Event("acme", "unifi.vpn", "ipsec_keepalive")));
        Assert.Null(filter.Match(Event("dg", "unifi.vpn", "")));
        Assert.Null(filter.Match(Event("dg", "unifi.firewall", "ipsec_keepalive")));

        filter.Flush();
        Assert.Equal(2, rules.Reported[Keepalives.Id]);
        filter.Flush();
        Assert.Equal(2, rules.Reported[Keepalives.Id]); // counters reset after flush
    }

    [Fact]
    public void Tenant_scoped_rules_only_apply_to_that_tenant()
    {
        var rule = Keepalives with { Id = Guid.NewGuid(), TenantSlug = "acme" };
        var filter = new DropFilter(new FixedRules(rule));
        Assert.Null(filter.Match(Event("dg", "unifi.vpn", "ipsec_keepalive")));
        Assert.NotNull(filter.Match(Event("acme", "unifi.vpn", "ipsec_keepalive")));
    }

    [Fact]
    public void Dataset_prefix_and_whole_dataset_rules()
    {
        var all = new DropRule(Guid.NewGuid(), "no vpn", null, "unifi.*", null, DropMatch.Any, null);
        var filter = new DropFilter(new FixedRules(all));
        Assert.NotNull(filter.Match(Event("dg", "unifi.vpn")));
        Assert.NotNull(filter.Match(Event("dg", "unifi.system")));
        Assert.Null(filter.Match(Event("dg", "syslog")));
    }

    [Theory]
    [InlineData(DropMatch.Contains, "DPD", true)]
    [InlineData(DropMatch.StartsWith, "14[ENC]", true)]
    [InlineData(DropMatch.Regex, @"^\d+\[ENC\] (parsed|generating) INFORMATIONAL", false)]
    [InlineData(DropMatch.Regex, @"QUICK_MODE request \d+", true)]
    public void Message_conditions(DropMatch match, string value, bool dropped)
    {
        var rule = new DropRule(Guid.NewGuid(), "msg", null, null, "message", match, value);
        var filter = new DropFilter(new FixedRules(rule));
        var e = Event("dg", "unifi.vpn", message: "14[ENC] parsed QUICK_MODE request 1017869010 [ HASH N(DPD) ]");
        Assert.Equal(dropped, filter.Match(e) is not null);
    }
}
