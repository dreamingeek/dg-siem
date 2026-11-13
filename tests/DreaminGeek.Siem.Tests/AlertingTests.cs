using System.Net;
using System.Text.Json.Nodes;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data.Entities;

namespace DreaminGeek.Siem.Tests;

public class AlertingTests
{
    private static AlertRule Rule(AlertCondition condition = AlertCondition.AnyResults, long threshold = 0, AlertTrigger trigger = AlertTrigger.Once, string? suppressBy = null) =>
        new() { Name = "Blocked sources", Query = "dataset=unifi.firewall", Condition = condition, Threshold = threshold, Trigger = trigger, SuppressBy = suppressBy };

    [Theory]
    [InlineData(AlertCondition.AnyResults, 0, 0, false)]
    [InlineData(AlertCondition.AnyResults, 0, 1, true)]
    [InlineData(AlertCondition.CountGreaterThan, 100, 100, false)]
    [InlineData(AlertCondition.CountGreaterThan, 100, 101, true)]
    [InlineData(AlertCondition.CountLessThan, 1, 0, true)]
    [InlineData(AlertCondition.CountLessThan, 1, 1, false)]
    public void ConditionsCompareTheCount(AlertCondition condition, long threshold, long count, bool expected) =>
        Assert.Equal(expected, AlertEvaluator.ConditionMet(condition, threshold, count));

    [Theory]
    [InlineData("15m", 15)]
    [InlineData("-1h", 60)]
    [InlineData("1d", 1440)]
    public void LookbackParses(string range, int minutes) =>
        Assert.Equal(TimeSpan.FromMinutes(minutes), AlertEvaluator.ParseLookback(range));

    [Theory]
    [InlineData("soon")]
    [InlineData("60d")]
    public void BadLookbackIsRejected(string range) =>
        Assert.Throws<AlertRuleException>(() => AlertEvaluator.ParseLookback(range));

    private static readonly string[] Columns = ["src", "count"];
    private static readonly List<object?[]> Rows = [["10.0.0.5", 120UL], ["10.0.0.9", 300UL], ["10.0.0.5", 7UL]];

    [Fact]
    public void TriggerOnceIsOneAlertWithTheRows()
    {
        var groups = AlertEvaluator.Groups(Rule(), Columns, Rows, conditionMet: true);
        var group = Assert.Single(groups);
        Assert.Equal(string.Empty, group.Key);
        Assert.Equal(3, group.Rows.Count);
    }

    [Fact]
    public void NothingFiresWhenTheConditionFails() =>
        Assert.Empty(AlertEvaluator.Groups(Rule(), Columns, Rows, conditionMet: false));

    [Fact]
    public void PerResultKeysOnTextColumnsNotCounts()
    {
        var groups = AlertEvaluator.Groups(Rule(trigger: AlertTrigger.PerResult), Columns, Rows, conditionMet: true);
        Assert.Equal(["src=10.0.0.5", "src=10.0.0.9"], groups.Select(g => g.Key));
        Assert.Equal(2, groups[0].Rows.Count);
    }

    [Fact]
    public void PerResultSkipsRowsWithAnEmptyKey()
    {
        List<object?[]> rows = [["", 40UL], ["10.0.0.9", 3UL]];
        var groups = AlertEvaluator.Groups(Rule(trigger: AlertTrigger.PerResult), Columns, rows, conditionMet: true);
        Assert.Equal("src=10.0.0.9", Assert.Single(groups).Key);
    }

    [Theory]
    [InlineData("dataset=unifi.firewall\n| stats count() as matched")]
    [InlineData("dataset=unifi.firewall | head 5\n| stats count() as matched")]
    [InlineData("dataset=unifi.firewall\n| head 20")]
    public void EvaluatorQueryExtensionsParse(string query) =>
        new DreaminGeek.Siem.Query.PipeParser().Parse(query.Replace("\\n", "\n", StringComparison.Ordinal));

    [Fact]
    public void SuppressByAcceptsShortcutsForColumnNames()
    {
        string[] columns = ["source.ip", "destination.port", "count"];
        List<object?[]> rows = [["10.0.0.5", 22L, 5UL]];
        var groups = AlertEvaluator.Groups(Rule(trigger: AlertTrigger.PerResult, suppressBy: "src"), columns, rows, conditionMet: true);
        Assert.Equal("source.ip=10.0.0.5", Assert.Single(groups).Key);
    }

    [Fact]
    public void FewerThanIsAlwaysOneAlert()
    {
        var groups = AlertEvaluator.Groups(Rule(AlertCondition.CountLessThan, 1, AlertTrigger.PerResult), [], [], conditionMet: true);
        Assert.Single(groups);
    }

    [Fact]
    public void RecipientsSplitAndValidate()
    {
        Assert.Equal(["a@example.com", "b@example.com"], AlertDispatcher.Recipients("a@example.com; b@example.com, A@example.com"));
        Assert.Null(AlertDispatcher.InvalidRecipient("a@example.com, b@example.com"));
        Assert.Equal("not-an-address", AlertDispatcher.InvalidRecipient("a@example.com, not-an-address"));
    }

    [Fact]
    public void NextRunFollowsTheCronAfterTheLastRun()
    {
        var rule = Rule();
        rule.Schedule = "*/5 * * * *";
        rule.LastRunAt = new DateTimeOffset(2026, 11, 11, 14, 2, 30, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 11, 11, 14, 5, 0, TimeSpan.Zero), AlertRunner.NextRun(rule, TimeZoneInfo.Utc));
    }

    [Fact]
    public void DailyScheduleUsesTheConfiguredZone()
    {
        var rule = Rule();
        rule.Schedule = "0 8 * * *";
        rule.LastRunAt = new DateTimeOffset(2026, 11, 11, 0, 0, 0, TimeSpan.Zero);
        var chicago = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
        // 08:00 CST is 14:00 UTC.
        Assert.Equal(new DateTimeOffset(2026, 11, 11, 14, 0, 0, TimeSpan.Zero), AlertRunner.NextRun(rule, chicago)!.Value.ToUniversalTime());
    }

    [Fact]
    public void BadScheduleIsRejected() =>
        Assert.Throws<AlertRuleException>(() => AlertRunner.ParseSchedule("every five minutes"));

    [Fact]
    public void MessageCarriesTheFactsAndEscapesHtml()
    {
        var rule = Rule(AlertCondition.CountGreaterThan, 100, AlertTrigger.PerResult);
        rule.Severity = AlertSeverity.High;
        rule.Description = "Check <the> firewall";
        var tenant = new Tenant { Slug = "acme", Name = "Acme" };
        var group = new AlertGroup("src=10.0.0.9", "src=10.0.0.9", [["10.0.0.9", 300UL]]);
        var evaluation = new AlertEvaluation(300, false, true, Columns, [["10.0.0.9", 300UL]], [group]);
        var from = new DateTimeOffset(2026, 11, 11, 14, 0, 0, TimeSpan.Zero);
        var message = AlertMessage.Build(rule, tenant, group, evaluation, from, from.AddMinutes(15), Guid.Empty,
            new GeneralSettings("https://siem.example.com/", "UTC"));

        Assert.Equal("Blocked sources - src=10.0.0.9 (acme)", message.Title);
        Assert.Equal("[DG SIEM] High: Blocked sources - src=10.0.0.9 (acme)", message.Subject);
        Assert.Contains("Matched: 300 results (alerting above 100)", message.TicketLines);
        Assert.Contains("src=10.0.0.9, count=300", message.TicketLines);
        Assert.Contains("Check &lt;the&gt; firewall", message.Html, StringComparison.Ordinal);
        Assert.DoesNotContain("<the>", message.Html, StringComparison.Ordinal);
        Assert.StartsWith("https://siem.example.com/search?q=dataset%3Dunifi.firewall&from=2026-11-11T14%3A00%3A00", message.SearchLink, StringComparison.Ordinal);
        Assert.EndsWith("&tenant=acme", message.SearchLink, StringComparison.Ordinal);
    }

    [Fact]
    public void HealthAlertLinksToHealthAndShowsNoQuery()
    {
        var rule = new AlertRule { Name = "A log source went quiet", Query = string.Empty, Kind = AlertRuleKind.QuietSources, Severity = AlertSeverity.High };
        string[] columns = ["source", "last event", "silent for", "usually silent at most"];
        object?[] row = ["unifi.firewall from gw1", "Thu 12 Nov 21:51", "3 h 2 min", "0 min"];
        var group = new AlertGroup("quiet:acme|unifi.firewall|gw1", "unifi.firewall from gw1 went quiet", [row]);
        var now = new DateTimeOffset(2026, 11, 13, 1, 0, 0, TimeSpan.Zero);
        var message = AlertMessage.Build(rule, new Tenant { Slug = "acme", Name = "Acme" }, group,
            new AlertEvaluation(1, false, true, columns, [row], [group]), now.AddHours(-1), now, Guid.Empty,
            new GeneralSettings("https://siem.example.com/", "UTC"));

        Assert.Equal("[DG SIEM] High: A log source went quiet - unifi.firewall from gw1 went quiet (acme)", message.Subject);
        Assert.Equal("https://siem.example.com/admin/health?tenant=acme", message.SearchLink);
        Assert.Contains("Found: unifi.firewall from gw1 went quiet", message.TicketLines);
        Assert.Contains("source=unifi.firewall from gw1, last event=Thu 12 Nov 21:51, silent for=3 h 2 min, usually silent at most=0 min", message.TicketLines);
        Assert.DoesNotContain(message.TicketLines, l => l.StartsWith("Query", StringComparison.Ordinal) || l.StartsWith("Matched", StringComparison.Ordinal));
        Assert.Contains("Open Health", message.Html, StringComparison.Ordinal);
    }

    [Fact]
    public void MessageHasNoLinksWithoutAPublicUrl()
    {
        var group = new AlertGroup(string.Empty, string.Empty, []);
        var message = AlertMessage.Build(Rule(), new Tenant { Slug = "dg", Name = "Dreamin Geek" }, group,
            new AlertEvaluation(4, true, true, [], [], [group]), DateTimeOffset.UtcNow.AddMinutes(-15), DateTimeOffset.UtcNow, Guid.Empty, SettingsStore.DefaultGeneral);
        Assert.Null(message.SearchLink);
        Assert.Contains("Matched: 4 events", message.TicketLines);
    }

    [Fact]
    public void BlockNoteIsParagraphsAndALink()
    {
        var blocks = JsonNode.Parse(AlgaPsaClient.BlockNote(["first", "", "third"], "https://siem.example.com/x"))!.AsArray();
        Assert.Equal(4, blocks.Count);
        Assert.All(blocks, b => Assert.Equal("paragraph", b!["type"]!.GetValue<string>()));
        Assert.Equal("first", blocks[0]!["content"]![0]!["text"]!.GetValue<string>());
        Assert.Empty(blocks[1]!["content"]!.AsArray());
        Assert.Equal("https://siem.example.com/x", blocks[3]!["content"]![0]!["href"]!.GetValue<string>());
    }

    [Fact]
    public async Task CreateTicketUsesTheBoardsOpenDefaultStatus()
    {
        var handler = new FakePsa();
        handler.Responses["GET /api/v1/tickets/statuses?board_id=b1"] = (HttpStatusCode.OK,
            """{"data":[{"status_id":"closed","is_closed":true,"is_default":true},{"status_id":"new","is_closed":false,"is_default":true},{"status_id":"wip","is_closed":false}]}""");
        handler.Responses["POST /api/v1/tickets"] = (HttpStatusCode.Created, """{"data":{"ticket_id":"t-1","ticket_number":"TIC1042"}}""");
        var client = new AlgaPsaClient(new FakeFactory(handler));
        var settings = new PsaSettings("https://psa.example.com", "key-123", null, new Dictionary<AlertSeverity, PsaRef>());

        var ticket = await client.CreateTicketAsync(settings,
            new NewPsaTicket("[DG SIEM] Blocked sources (acme)", "c1", "b1", "p1", ["line"], "https://siem.example.com/x", "firing-1"), CancellationToken.None);

        Assert.Equal(new PsaTicket("t-1", "TIC1042"), ticket);
        Assert.Equal("key-123", handler.ApiKeys.Distinct().Single());
        var body = JsonNode.Parse(handler.Bodies["POST /api/v1/tickets"])!;
        Assert.Equal("new", body["status_id"]!.GetValue<string>());
        Assert.Equal("c1", body["client_id"]!.GetValue<string>());
        Assert.Equal("p1", body["priority_id"]!.GetValue<string>());
        Assert.Equal("dg-siem", body["external_links"]![0]!["system"]!.GetValue<string>());
        Assert.Equal("firing-1", body["external_links"]![0]!["external_id"]!.GetValue<string>());
        Assert.StartsWith("[{", body["attributes"]!["description"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PsaErrorsAreReadable()
    {
        var handler = new FakePsa();
        handler.Responses["GET /api/v1/boards?limit=100"] = (HttpStatusCode.Unauthorized, """{"error":{"message":"Invalid API key"}}""");
        var client = new AlgaPsaClient(new FakeFactory(handler));
        var ex = await Assert.ThrowsAsync<PsaException>(() =>
            client.BoardsAsync(new PsaSettings("https://psa.example.com", "bad", null, new Dictionary<AlertSeverity, PsaRef>()), CancellationToken.None));
        Assert.Equal("AlgaPSA said 401 Unauthorized: Invalid API key. Check the API key.", ex.Message);
    }

    [Fact]
    public async Task UnconfiguredPsaSaysWhereToSetItUp()
    {
        var client = new AlgaPsaClient(new FakeFactory(new FakePsa()));
        var ex = await Assert.ThrowsAsync<PsaException>(() => client.BoardsAsync(SettingsStore.EmptyPsa, CancellationToken.None));
        Assert.Contains("Notifications", ex.Message, StringComparison.Ordinal);
    }

    private sealed class FakeFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class FakePsa : HttpMessageHandler
    {
        public Dictionary<string, (HttpStatusCode Status, string Body)> Responses { get; } = [];
        public Dictionary<string, string> Bodies { get; } = [];
        public List<string> ApiKeys { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var key = $"{request.Method} {request.RequestUri!.PathAndQuery}";
            ApiKeys.Add(request.Headers.GetValues("x-api-key").Single());
            if (request.Content is not null)
            {
                Bodies[key] = await request.Content.ReadAsStringAsync(cancellationToken);
            }
            var (status, body) = Responses.TryGetValue(key, out var r) ? r : (HttpStatusCode.NotFound, """{"error":{"message":"no route"}}""");
            return new HttpResponseMessage(status) { Content = new StringContent(body) };
        }
    }
}
