using System.Net;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Ingest.Metrics;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Logging.Abstractions;

namespace DreaminGeek.Siem.Tests;

public class PrometheusTextTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);

    private static List<MetricSample> Parse(string text, string header = "# dgsiem_scrape duration_seconds=0.042") =>
        PrometheusText.Parse(new RawEnvelope(At, "prometheus:netprox", "netprox.example.net:81", header + "\n" + text), "acme");

    private const string Exposition = """
        # HELP http_requests_total Requests handled.
        # TYPE http_requests_total counter
        http_requests_total{method="GET",code="200"} 1027
        http_requests_total{method="POST",code="500",path="/a\"b\\c\nd"} 3 1731585600000
        # TYPE process_resident_memory_bytes gauge
        process_resident_memory_bytes 2.4576e+07
        # TYPE request_duration_seconds histogram
        request_duration_seconds_bucket{le="0.1"} 50
        request_duration_seconds_bucket{le="+Inf"} 60
        request_duration_seconds_sum 12.5
        request_duration_seconds_count 60
        # TYPE rpc_seconds summary
        rpc_seconds{quantile="0.99"} NaN
        go_goroutines 42 # {trace_id="abc"} 1.0
        {"http.server.active_requests",service="web"} 7
        temperature_celsius{job="sensor",instance="probe-1"} -3.5
        """;

    [Fact]
    public void Reads_samples_with_labels_types_and_timestamps()
    {
        var samples = Parse(Exposition);
        MetricSample One(string name, string? label = null, string? value = null) =>
            samples.Single(s => s.Name == name && (label is null || s.Labels.GetValueOrDefault(label) == value));

        var get = One("http_requests_total", "method", "GET");
        Assert.Equal(1027, get.Value);
        Assert.Equal("counter", get.Type);
        Assert.Equal(At, get.Timestamp);
        Assert.Equal(["code", "instance", "job", "method"], get.Labels.Keys);
        Assert.Equal("netprox", get.Labels["job"]);
        Assert.Equal("netprox.example.net:81", get.Labels["instance"]);

        var post = One("http_requests_total", "method", "POST");
        Assert.Equal("/a\"b\\c\nd", post.Labels["path"]);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1731585600000), post.Timestamp);

        Assert.Equal(24_576_000, One("process_resident_memory_bytes").Value);
        Assert.Equal("gauge", One("process_resident_memory_bytes").Type);
        Assert.Equal(60, One("request_duration_seconds_bucket", "le", "+Inf").Value);
        Assert.Equal("histogram", One("request_duration_seconds_count").Type);
        Assert.DoesNotContain(samples, s => s.Name == "rpc_seconds"); // NaN
        Assert.Equal(42, One("go_goroutines").Value); // exemplar ignored
        Assert.Equal(7, One("http.server.active_requests").Value);

        // A target's own job/instance labels are kept as exported_*, as Prometheus does.
        var temperature = One("temperature_celsius");
        Assert.Equal(-3.5, temperature.Value);
        Assert.Equal("netprox", temperature.Labels["job"]);
        Assert.Equal("sensor", temperature.Labels["exported_job"]);
        Assert.Equal("probe-1", temperature.Labels["exported_instance"]);
        Assert.All(samples, s => Assert.Equal("acme", s.TenantId));
    }

    [Fact]
    public void Every_scrape_records_up_duration_and_sample_count()
    {
        var samples = Parse(Exposition);
        Assert.Equal(1, samples.Single(s => s.Name == "up").Value);
        Assert.Equal(0.042, samples.Single(s => s.Name == "scrape_duration_seconds").Value);
        Assert.Equal(samples.Count - 3, samples.Single(s => s.Name == "scrape_samples_scraped").Value);
        Assert.Equal(["instance", "job"], samples.Single(s => s.Name == "up").Labels.Keys);
    }

    [Fact]
    public void A_failed_scrape_is_up_0_and_nothing_else()
    {
        var samples = Parse("", "# dgsiem_scrape error=Connection refused (netprox.example.net:81)");
        Assert.Equal(["up", "scrape_samples_scraped"], samples.Select(s => s.Name));
        Assert.Equal(0, samples[0].Value);
        Assert.Equal(0, samples[1].Value);
    }

    [Fact]
    public void Garbage_lines_are_skipped()
    {
        var samples = Parse("<html>not metrics</html>\nok_metric 1\nbroken{a=\"x\" 2\n{=\"x\"} 3\nname{a=\"b\"} notanumber");
        Assert.Equal(["ok_metric", "up", "scrape_duration_seconds", "scrape_samples_scraped"], samples.Select(s => s.Name));
    }

    [Fact]
    public void Only_prometheus_envelopes_are_scrapes()
    {
        Assert.True(PrometheusText.IsScrape(new RawEnvelope(At, "prometheus:x", null, "")));
        Assert.False(PrometheusText.IsScrape(new RawEnvelope(At, "hec", null, "")));
    }
}

public class MetricTargetTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);

    private static DreaminGeek.Siem.Storage.ClickHouse.MetricTarget Target(TimeSpan ago, bool up, TimeSpan? every) =>
        new("acme", "netprox", "netprox.example.net:81", Now - ago, up, null, 120, 0.04, every);

    [Fact]
    public void A_target_is_up_down_or_missing()
    {
        Assert.Equal(DreaminGeek.Siem.Storage.ClickHouse.TargetState.Up, Target(TimeSpan.FromSeconds(30), true, TimeSpan.FromMinutes(1)).StateAt(Now));
        Assert.Equal(DreaminGeek.Siem.Storage.ClickHouse.TargetState.Down, Target(TimeSpan.FromSeconds(30), false, TimeSpan.FromMinutes(1)).StateAt(Now));
        // Missing after three intervals, but never sooner than 5 minutes.
        Assert.Equal(DreaminGeek.Siem.Storage.ClickHouse.TargetState.Up, Target(TimeSpan.FromMinutes(4), true, TimeSpan.FromSeconds(15)).StateAt(Now));
        Assert.Equal(DreaminGeek.Siem.Storage.ClickHouse.TargetState.Missing, Target(TimeSpan.FromMinutes(6), true, TimeSpan.FromSeconds(15)).StateAt(Now));
        Assert.Equal(DreaminGeek.Siem.Storage.ClickHouse.TargetState.Up, Target(TimeSpan.FromMinutes(25), true, TimeSpan.FromMinutes(10)).StateAt(Now));
        Assert.Equal(DreaminGeek.Siem.Storage.ClickHouse.TargetState.Missing, Target(TimeSpan.FromMinutes(31), true, TimeSpan.FromMinutes(10)).StateAt(Now));
    }

    [Fact]
    public void Scrape_errors_are_kept_until_the_next_good_scrape()
    {
        var errors = new ScrapeErrors();
        errors.Record("acme", "netprox", "a:81", Now, "server returned HTTP status 401 Unauthorized");
        Assert.Equal("server returned HTTP status 401 Unauthorized", errors.Get("acme", "netprox", "a:81"));
        Assert.Null(errors.Get("globex", "netprox", "a:81"));
        errors.Record("acme", "netprox", "a:81", Now, null);
        Assert.Null(errors.Get("acme", "netprox", "a:81"));
    }

    [Fact]
    public void The_scrape_error_comes_out_of_the_envelope()
    {
        PrometheusText.Parse(new RawEnvelope(Now, "prometheus:netprox", "a:81", "# dgsiem_scrape error=Connection refused"), "acme", out var error);
        Assert.Equal("Connection refused", error);
        PrometheusText.Parse(new RawEnvelope(Now, "prometheus:netprox", "a:81", "# dgsiem_scrape duration_seconds=0.1\nx 1"), "acme", out error);
        Assert.Null(error);
    }
}

public class MstatsTests
{
    private static CompiledQuery Compile(string query, params string[] tenants) => ClickHouseCompilerTests.Compile(query, tenants);

    [Fact]
    public void Parses_aggregations_filters_by_and_span()
    {
        var p = new PipeParser().Parse("""| mstats rate(http_requests_total) as rps, avg(up) where job="netprox" instance!="test*" by instance, code span=5m""");
        var m = Assert.IsType<MstatsCommand>(Assert.Single(p.Commands));
        Assert.Equal([("rate", "http_requests_total", "rps"), ("avg", "up", null)], m.Aggregations.Select(a => (a.Function, a.Field, a.Alias)));
        Assert.Equal([("job", false, "netprox"), ("instance", true, "test*")], m.Filters.Select(f => (f.Label, f.Negated, f.Value)));
        Assert.Equal(["instance", "code"], m.By);
        Assert.Equal(TimeSpan.FromMinutes(5), m.Span);

        // Without the leading pipe too.
        Assert.IsType<MstatsCommand>(Assert.Single(new PipeParser().Parse("mstats latest(up) by instance").Commands));
    }

    [Fact]
    public void Compiles_to_a_tenant_scoped_parameterized_query_on_the_metrics_table()
    {
        var q = Compile("""| mstats rate(http_requests_total) where job="net'prox" by instance span=5m""", "acme", "globex");
        Assert.Equal(ResultShape.Timechart, q.Shape);
        Assert.Equal(["_time", "instance", "rate(http_requests_total)"], q.Columns);
        Assert.Contains("FROM dgsiem.metrics WHERE tenant_id IN {p0:Array(String)}", q.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("dgsiem.events", q.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("net'prox", q.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("http_requests_total", q.Sql.Replace("`rate(http_requests_total)`", "", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Contains("lagInFrame(value)", q.Sql, StringComparison.Ordinal);
        Assert.Equal(new[] { "acme", "globex" }, (string[])q.Parameters["p0"]);
        Assert.Contains("net'prox", q.Parameters.Values);
    }

    [Fact]
    public void Without_a_span_it_is_a_table_and_later_commands_work()
    {
        var q = Compile("| mstats max(process_resident_memory_bytes) as mem by instance | where mem > 1000000 | sort -mem | head 5");
        Assert.Equal(ResultShape.Table, q.Shape);
        Assert.Equal(["instance", "mem"], q.Columns);
        Assert.EndsWith("LIMIT 5", q.Sql, StringComparison.Ordinal);
        Assert.Contains("ORDER BY `mem` DESC", q.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Several_labels_make_one_series_column_in_a_timechart()
    {
        var q = Compile("| mstats avg(up) by job, instance span=1m");
        Assert.Equal(["_time", "job/instance", "avg(up)"], q.Columns);
    }

    [Theory]
    [InlineData("error | mstats avg(up)", "mstats starts the search")]
    [InlineData("* | stats count | mstats avg(up)", "mstats has to come first")]
    [InlineData("| mstats dc(up)", "mstats can't do dc()")]
    [InlineData("| mstats avg(up) where job>3", "Label filters use = or !=")]
    [InlineData("| mstats by instance", "mstats needs an aggregation")]
    [InlineData("| mstats count", "Expected an aggregation of a metric")]
    public void Explains_mistakes(string query, string message) =>
        Assert.Contains(message, Assert.ThrowsAny<QueryParseException>(() => Compile(query)).Message, StringComparison.Ordinal);
}

public class PrometheusInputTests
{
    private sealed class FakeExporter(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }

    private static (List<RawEnvelope> Sent, FakeExporter Exporter, PrometheusInput Input) Create(HttpStatusCode status, string body, InputConfig config)
    {
        var sent = new List<RawEnvelope>();
        var exporter = new FakeExporter(status, body);
        var input = new PrometheusInput(config, null!, NullLogger.Instance) { Emit = e => { lock (sent) { sent.Add(e); } return true; }, Handler = exporter };
        return (sent, exporter, input);
    }

    private static InputConfig Config() => new()
    {
        Type = InputType.Prometheus,
        Job = "netprox",
        Targets = ["netprox.example.net:81", "backup.example.net:81"],
        Authorization = new ScrapeAuthorization { Credentials = "s3cr3t-token" },
    };

    [Fact]
    public async Task Scrapes_every_target_with_the_token_and_ships_the_page()
    {
        var (sent, exporter, input) = Create(HttpStatusCode.OK, "up_metric 1\n", Config());
        using (input)
        {
            await input.ScrapeAllAsync(CancellationToken.None);
        }
        Assert.Equal(2, sent.Count);
        Assert.Equal(["http://backup.example.net:81/metrics", "http://netprox.example.net:81/metrics"],
            exporter.Requests.Select(r => r.RequestUri!.ToString()).Order(StringComparer.Ordinal));
        Assert.All(exporter.Requests, r => Assert.Equal("Bearer s3cr3t-token", r.Headers.Authorization?.ToString()));
        var envelope = sent.Single(e => e.SourceAddress == "netprox.example.net:81");
        Assert.Equal("prometheus:netprox", envelope.Input);
        Assert.StartsWith("# dgsiem_scrape duration_seconds=", envelope.Message, StringComparison.Ordinal);
        Assert.EndsWith("\nup_metric 1\n", envelope.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_scrape_is_shipped_as_a_failure()
    {
        var (sent, _, input) = Create(HttpStatusCode.Unauthorized, "go away", Config());
        using (input)
        {
            await input.ScrapeAllAsync(CancellationToken.None);
        }
        Assert.All(sent, e => Assert.Equal("# dgsiem_scrape error=server returned HTTP status 401 Unauthorized", e.Message));
        var samples = PrometheusText.Parse(sent[0], "acme");
        Assert.Equal(0, samples.Single(s => s.Name == "up").Value);
    }

    [Fact]
    public void Config_is_checked_when_saved()
    {
        AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"Prometheus","job":"netprox","targets":["netprox.example.net:81"],"authorization":{"credentials":"t0k3n"},"scrapeInterval":"30s"}]}""");
        void Bad(string input, string error) => Assert.Contains(error,
            Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig($$"""{"inputs":[{{input}}]}""")).Message, StringComparison.Ordinal);
        Bad("""{"type":"Prometheus","targets":["a:1"]}""", "needs a \"job\"");
        Bad("""{"type":"Prometheus","job":"x"}""", "needs \"targets\"");
        Bad("""{"type":"Prometheus","job":"x","targets":["http://a:1/metrics"]}""", "should be host:port");
        Bad("""{"type":"Prometheus","job":"x","targets":["a:1"],"scrapeInterval":"1s"}""", "between 5s and 1h");
        Bad("""{"type":"Prometheus","job":"x","targets":["a:1"],"scrapeInterval":"often"}""", "isn't a duration");
        Bad("""{"type":"Prometheus","job":"x","targets":["a:1"],"scheme":"ftp"}""", "http or https");
        Bad("""{"type":"Prometheus","job":"x","targets":["a:1"],"authorization":{}}""", "needs \"credentials\"");
    }

    [Fact]
    public void Older_agents_are_not_given_a_prometheus_input()
    {
        var config = AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"Prometheus","job":"x","targets":["a:1"]}]}""");
        Assert.Contains("need agent 0.6.0 or later", Assert.Throws<AdminException>(() => AdminService.RequireAgentSupports(config, "0.5.2")).Message, StringComparison.Ordinal);
        AdminService.RequireAgentSupports(config, "0.6.0");
        AdminService.RequireAgentSupports(config, null);
        AdminService.RequireAgentSupports(AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"SyslogUdp","port":514}]}"""), "0.4.0");
    }
}
