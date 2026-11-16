using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Ingest.Otlp;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;

namespace DreaminGeek.Siem.Tests;

/// <summary>
/// The OTLP input end to end, with the OpenTelemetry .NET SDK as the sender: its OTLP exporter talks to the agent's
/// input over HTTP/protobuf and gRPC, and the server's decoder turns what the agent buffered into events and samples.
/// </summary>
public sealed class OtlpTests
{
    private const string Token = "otel-test-token-1234";

    private static readonly ParserRegistry Parsers = new([new TraefikParser(), new SyslogParser()]);

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class Agent : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cts = new(TimeSpan.FromSeconds(60));
        private readonly Task _run;
        public List<RawEnvelope> Sent { get; } = [];
        public int Port { get; } = FreePort();

        public Agent(bool grpc)
        {
            var config = new InputConfig { Type = grpc ? InputType.OtlpGrpc : InputType.Otlp, BindAddress = "127.0.0.1", Port = Port, Tokens = [Token], Job = "apps" };
            var input = new OtlpInput(config, null!, null, NullLogger.Instance, grpc) { Emit = e => { lock (Sent) { Sent.Add(e); } return true; } };
            _run = input.RunAsync(_cts.Token);
        }

        public async Task WaitUntilListeningAsync()
        {
            for (var i = 0; i < 100; i++)
            {
                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(IPAddress.Loopback, Port);
                    return;
                }
                catch (SocketException)
                {
                    await Task.Delay(50);
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            await _run;
            _cts.Dispose();
        }
    }

    /// <summary>Sends logs and metrics with the OpenTelemetry SDK, the way an instrumented app would.</summary>
    private static void SendWithSdk(Agent agent, bool grpc, out string traceId)
    {
        var protocol = grpc ? OtlpExportProtocol.Grpc : OtlpExportProtocol.HttpProtobuf;
        Uri Endpoint(string path) => new(grpc ? $"http://127.0.0.1:{agent.Port}" : $"http://127.0.0.1:{agent.Port}{path}");
        void Exporter(OtlpExporterOptions o, string path)
        {
            o.Endpoint = Endpoint(path);
            o.Protocol = protocol;
            o.Headers = $"Authorization=Bearer {Token}";
        }
        var resource = ResourceBuilder.CreateEmpty().AddService("billing", serviceNamespace: "shop", serviceVersion: "1.2.3", serviceInstanceId: "billing-1")
            .AddAttributes([new("host.name", "app01")]);

        using var activity = new Activity("checkout").Start();
        traceId = activity.TraceId.ToHexString();
        using (var loggers = LoggerFactory.Create(b => b.AddOpenTelemetry(o =>
        {
            o.SetResourceBuilder(resource);
            o.IncludeFormattedMessage = true;
            o.AddOtlpExporter(e => Exporter(e, "/v1/logs"));
        })))
        {
            var log = loggers.CreateLogger("Billing.Orders");
#pragma warning disable CA1848, CA2254 // A test sender, written the way apps often log.
            log.LogWarning("Order {OrderId} failed for {Customer}", 42, "acme");
            log.LogInformation("Order {OrderId} placed", 43);
#pragma warning restore CA1848, CA2254
        }
        activity.Stop();

        using var meter = new Meter("Billing");
        using var provider = Sdk.CreateMeterProviderBuilder().SetResourceBuilder(resource).AddMeter("Billing")
            .AddView("http.server.duration", new ExplicitBucketHistogramConfiguration { Boundaries = [10, 100, 1000] })
            .AddOtlpExporter((e, reader) =>
            {
                Exporter(e, "/v1/metrics");
                reader.TemporalityPreference = MetricReaderTemporalityPreference.Cumulative;
            })
            .Build();
        var orders = meter.CreateCounter<long>("orders.placed");
        orders.Add(3, new KeyValuePair<string, object?>("payment.method", "card"));
        orders.Add(2, new KeyValuePair<string, object?>("payment.method", "card"));
        var duration = meter.CreateHistogram<double>("http.server.duration", unit: "ms");
        foreach (var ms in new[] { 5.0, 50, 50, 500, 5000 })
        {
            duration.Record(ms, new KeyValuePair<string, object?>("job", "theirs"));
        }
        meter.CreateObservableGauge("queue.depth", () => 7);
        Assert.True(provider.ForceFlush(10_000));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_sdk_sends_logs_and_metrics_over_http_and_grpc(bool grpc)
    {
        await using var agent = new Agent(grpc);
        await agent.WaitUntilListeningAsync();
        SendWithSdk(agent, grpc, out var traceId);

        List<RawEnvelope> sent;
        lock (agent.Sent)
        {
            sent = [.. agent.Sent];
        }
        Assert.All(sent, e => Assert.Equal("otlp:apps", e.Input));
        Assert.All(sent, e => Assert.Equal("127.0.0.1", e.SourceAddress));

        var events = sent.SelectMany(e => OtlpConvert.ToEvents(e, "acme", Parsers) ?? []).ToList();
        Assert.Equal(2, events.Count);
        var failed = events.Single(e => e.LogLevel == "warn");
        Assert.Equal("Order 42 failed for acme", failed.Message);
        Assert.Equal("otel.billing", failed.EventDataset);
        Assert.Equal("otel", failed.EventModule);
        Assert.Equal("app01", failed.HostName);
        Assert.Equal("acme", failed.TenantId);
        Assert.Equal("42", failed.Fields["OrderId"]);
        Assert.Equal("acme", failed.Fields["Customer"]);
        Assert.Equal("billing", failed.Fields["service.name"]);
        Assert.Equal("1.2.3", failed.Fields["service.version"]);
        Assert.Equal("Billing.Orders", failed.Fields["otel.scope.name"]);
        Assert.Equal(traceId, failed.Fields["trace.id"]);
        Assert.Equal("apps", failed.Fields["otel.job"]);
        Assert.True(Math.Abs((failed.Timestamp - DateTimeOffset.UtcNow).TotalMinutes) < 2);
        Assert.Equal("info", events.Single(e => e.Message == "Order 43 placed").LogLevel);

        var samples = sent.SelectMany(e => OtlpConvert.ToSamples(e, "acme") ?? []).ToList();
        // Cumulative metrics are re-sent on every export; keep the latest of each series.
        samples = [.. samples.GroupBy(s => s.Name + string.Join(";", s.Labels.Select(l => l.Key + "=" + l.Value))).Select(g => g.Last())];
        var placed = samples.Single(s => s.Name == "orders_placed");
        Assert.Equal(5, placed.Value);
        Assert.Equal("counter", placed.Type);
        Assert.Equal("card", placed.Labels["payment_method"]);
        Assert.Equal("shop/billing", placed.Labels["job"]);
        Assert.Equal("billing-1", placed.Labels["instance"]);
        Assert.Equal("app01", placed.Labels["host_name"]);

        // Histogram: cumulative buckets, count and sum; the point's own "job" kept as exported_job.
        var buckets = samples.Where(s => s.Name == "http_server_duration_bucket").ToDictionary(s => s.Labels["le"], s => s.Value);
        Assert.Equal(new Dictionary<string, double> { ["10"] = 1, ["100"] = 3, ["1000"] = 4, ["+Inf"] = 5 }, buckets);
        Assert.Equal(5, samples.Single(s => s.Name == "http_server_duration_count").Value);
        Assert.Equal(5605, samples.Single(s => s.Name == "http_server_duration_sum").Value);
        Assert.Equal("theirs", samples.First(s => s.Name == "http_server_duration_count").Labels["exported_job"]);
        Assert.Equal(7, samples.Single(s => s.Name == "queue_depth").Value);
        Assert.Equal("gauge", samples.Single(s => s.Name == "queue_depth").Type);
    }

    [Fact]
    public async Task Requests_without_the_token_are_refused()
    {
        await using (var http = new Agent(grpc: false))
        {
            await http.WaitUntilListeningAsync();
            using var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{http.Port}") };
            var body = new ByteArrayContent([]);
            body.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/v1/logs", body)).StatusCode);
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await client.PostAsync("/v1/logs", new StringContent("x"))).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/v2/logs", body)).StatusCode);

            // Traces are accepted and dropped.
            var traces = new HttpRequestMessage(HttpMethod.Post, "/v1/traces") { Content = new ByteArrayContent([10, 0]) };
            traces.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");
            traces.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(traces)).StatusCode);
            Assert.Empty(http.Sent);
        }

        await using var grpc = new Agent(grpc: true);
        await grpc.WaitUntilListeningAsync();
        using var h2 = new HttpClient();
        var call = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{grpc.Port}/opentelemetry.proto.collector.logs.v1.LogsService/Export")
        {
            Content = new ByteArrayContent(new byte[5]),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        call.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        var response = await h2.SendAsync(call);
        Assert.Equal("16", response.Headers.GetValues("grpc-status").Single()); // UNAUTHENTICATED
    }

    [Fact]
    public void Json_requests_cover_every_metric_kind_and_log_body()
    {
        const string logs = """
            {"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"Edge Gateway"}}]},
              "scopeLogs":[{"scope":{"name":"edge"},"logRecords":[
                {"timeUnixNano":"1763208000000000000","severityNumber":"SEVERITY_NUMBER_ERROR","body":{"kvlistValue":{"values":[
                  {"key":"msg","value":{"stringValue":"upstream down"}},{"key":"retries","value":{"intValue":"3"}},
                  {"key":"tags","value":{"arrayValue":{"values":[{"stringValue":"a"},{"boolValue":true}]}}}]}},
                 "attributes":[{"key":"event.dataset","value":{"stringValue":"edge.errors"}}],
                 "traceId":"5B8EFFF798038103D269B633813FC60C","spanId":"0000000000000000"},
                {"observedTimeUnixNano":1763208001000000000,"severityText":"Warning","body":{"stringValue":"slow"}}]}]}]}
            """;
        var events = OtlpConvert.ToEvents(Envelope("logs", logs), "acme", Parsers)!;
        Assert.Equal("""{"msg":"upstream down","retries":3,"tags":["a",true]}""", events[0].Message);
        Assert.Equal("error", events[0].LogLevel);
        Assert.Equal("edge.errors", events[0].EventDataset);
        Assert.Equal("5b8efff798038103d269b633813fc60c", events[0].Fields["trace.id"]);
        Assert.False(events[0].Fields.ContainsKey("span.id"));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1763208000), events[0].Timestamp);
        Assert.Equal("warn", events[1].LogLevel);
        Assert.Equal("otel.edge_gateway", events[1].EventDataset);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1763208001), events[1].Timestamp);

        const string metrics = """
            {"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge"}}]},"scopeMetrics":[{"metrics":[
              {"name":"bytes.sent","sum":{"aggregationTemporality":"AGGREGATION_TEMPORALITY_DELTA","isMonotonic":true,
                "dataPoints":[{"timeUnixNano":"1763208000000000000","asInt":"2048"}]}},
              {"name":"rpc.latency","summary":{"dataPoints":[{"timeUnixNano":"1763208000000000000","count":"10","sum":2.5,
                "quantileValues":[{"quantile":0.5,"value":0.2},{"quantile":0.99,"value":0.9}]}]}},
              {"name":"payload","exponentialHistogram":{"aggregationTemporality":2,"dataPoints":[{"timeUnixNano":"1763208000000000000","count":"4","sum":40}]}},
              {"name":"temperature","gauge":{"dataPoints":[{"timeUnixNano":"1763208000000000000","asDouble":21.5,
                "attributes":[{"key":"room","value":{"stringValue":"rack"}}]}]}}]}]}]}
            """;
        var samples = OtlpConvert.ToSamples(Envelope("metrics", metrics), "acme")!;
        var bytes = samples.Single(s => s.Name == "bytes_sent");
        Assert.Equal((2048d, "untyped"), (bytes.Value, bytes.Type)); // delta: an amount per interval, not a counter
        Assert.Equal("edge", bytes.Labels["job"]);
        Assert.Equal("10.0.0.5", bytes.Labels["instance"]); // no instance id or host: the sender
        Assert.Equal(0.9, samples.Single(s => s.Name == "rpc_latency" && s.Labels["quantile"] == "0.99").Value);
        Assert.Equal(10, samples.Single(s => s.Name == "rpc_latency_count").Value);
        Assert.Equal(40, samples.Single(s => s.Name == "payload_sum").Value);
        Assert.Equal(21.5, samples.Single(s => s.Name == "temperature").Value);
        Assert.Equal("rack", samples.Single(s => s.Name == "temperature").Labels["room"]);
    }

    [Fact]
    public void A_traefik_line_sent_through_opentelemetry_is_still_traefik()
    {
        const string line = """{"ClientAddr":"198.51.100.24:49835","ClientHost":"198.51.100.24","DownstreamStatus":200,"Duration":287504981,"RequestHost":"office.backup.example.com","RequestMethod":"GET","RequestPath":"/","RequestProtocol":"HTTP/2.0","RouterName":"8-router@http","ServiceName":"8-service@http","StartUTC":"2026-11-12T05:04:42.879402116Z","time":"2026-11-12T05:04:43Z","level":"info","msg":""}""";
        var request = $$$"""
            {"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},
              "scopeLogs":[{"logRecords":[{"body":{"stringValue":{{{System.Text.Json.JsonSerializer.Serialize(line)}}}}}]}]}]}
            """;
        var e = OtlpConvert.ToEvents(Envelope("logs", request), "acme", Parsers)!.Single();
        Assert.Equal("traefik.access", e.EventDataset);
        Assert.Equal("198.51.100.24", e.SourceIp);
        Assert.Equal("traefik", e.Fields["service.name"]);
    }

    [Fact]
    public void Broken_requests_are_reported_not_half_read()
    {
        Assert.Throws<OtlpFormatException>(() => OtlpProtobuf.ReadLogs([0x0a, 0x10, 0x01])); // a length past the end
        Assert.Throws<OtlpFormatException>(() => OtlpProtobuf.ReadMetrics([0x00]));            // field number 0
        Assert.Throws<OtlpFormatException>(() => OtlpJson.ReadLogs("{\"resourceLogs\":"u8));
        Assert.Empty(OtlpProtobuf.ReadLogs([]));
        Assert.Null(OtlpConvert.ToEvents(new RawEnvelope(DateTimeOffset.UtcNow, "syslog-udp", null, "hello"), "acme", Parsers));
    }

    [Fact]
    public void Config_is_checked_when_saved()
    {
        var config = AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"Otlp","port":4318,"tokens":["otel-token-123"]},{"type":"OtlpGrpc","port":4317}]}""");
        Assert.Contains("need agent 0.8.0", Assert.Throws<AdminException>(() => AdminService.RequireAgentSupports(config, "0.7.0")).Message, StringComparison.Ordinal);
        AdminService.RequireAgentSupports(config, "0.8.0");
        Assert.Contains("OpenTelemetry tokens", Assert.Throws<AdminException>(() =>
            AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"Otlp","port":4318,"tokens":["short"]}]}""")).Message, StringComparison.Ordinal);
    }

    private static RawEnvelope Envelope(string signal, string json) =>
        OtlpPush.Envelope("apps", "10.0.0.5", signal, json: true, Encoding.UTF8.GetBytes(json));
}
