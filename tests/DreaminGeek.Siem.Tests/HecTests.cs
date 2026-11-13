using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Logging.Abstractions;

namespace DreaminGeek.Siem.Tests;

public sealed class HecTests
{
    private const string Token = "0b6c4f9e-2a8d-4c1b-9f0e-5d7a3b2c1e4f";

    private static readonly ParserRegistry Registry = new([new TraefikParser(), new UnifiParser(), new SyslogParser()]);

    private static LogEvent Parse(string hecJson, string? datasetHint = null) =>
        Registry.Parse(new RawEnvelope(new DateTimeOffset(2026, 11, 12, 16, 0, 0, TimeSpan.Zero), "hec", "10.0.1.50", hecJson, datasetHint), "dg");

    // ---- Agent: request bodies -------------------------------------------------------------

    [Fact]
    public void Events_can_be_concatenated_or_in_an_array()
    {
        var body = """{"event":"one"}{"event":{"a":1}} {"event":"three","time":1700000000}"""u8;
        var result = HecPayload.FromEvents(body);
        Assert.Null(result.Error);
        Assert.Equal(3, result.Events.Count);
        Assert.Equal("""{"event":{"a":1}}""", result.Events[1]);

        var array = HecPayload.FromEvents("""[{"event":"a"},{"event":"b"}]"""u8);
        Assert.Equal(2, array.Events.Count);
    }

    [Fact]
    public void Bad_events_are_rejected_with_splunk_codes()
    {
        Assert.Equal(12, HecPayload.FromEvents("""{"event":"ok"}{"host":"x"}"""u8) is { Error: { } e, InvalidIndex: 1 } ? e.Code : -1);
        Assert.Equal(13, HecPayload.FromEvents("""{"event":""}"""u8).Error?.Code);
        Assert.Equal(6, HecPayload.FromEvents("""{"event":"ok"} not json"""u8).Error?.Code);
        Assert.Equal(5, HecPayload.FromEvents("   "u8).Error?.Code);
    }

    [Fact]
    public void Raw_bodies_are_one_event_per_line()
    {
        var result = HecPayload.FromRaw("line one\r\n\nline two\n"u8, "web01", "/var/log/x", "nginx");
        Assert.Equal(2, result.Events.Count);
        Assert.Equal("""{"event":"line one","host":"web01","source":"/var/log/x","sourcetype":"nginx"}""", result.Events[0]);
    }

    // ---- Agent: live listener --------------------------------------------------------------

    [Fact]
    public async Task Listener_accepts_tokens_and_buffers_events()
    {
        var port = FreePort();
        var sent = new List<RawEnvelope>();
        var config = new InputConfig { Type = InputType.Hec, BindAddress = "127.0.0.1", Port = port, Tokens = [Token], Dataset = "myapp" };
        var input = new HecInput(config, null!, null, NullLogger.Instance) { Emit = e => { lock (sent) { sent.Add(e); } return true; } };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = input.RunAsync(cts.Token);
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
        await WaitForHealthAsync(http);

        // No token, wrong token.
        var none = await http.PostAsync("/services/collector/event", new StringContent("""{"event":"x"}"""));
        Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);
        var wrong = new HttpRequestMessage(HttpMethod.Post, "/services/collector/event") { Content = new StringContent("""{"event":"x"}""") };
        wrong.Headers.Authorization = new AuthenticationHeaderValue("DGSIEM", "not-the-token-at-all");
        Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(wrong)).StatusCode);

        // DGSIEM header, JSON events.
        var ok = new HttpRequestMessage(HttpMethod.Post, "/services/collector/event") { Content = new StringContent("""{"event":"hello","sourcetype":"app"}{"event":{"msg":"hi"}}""") };
        ok.Headers.Authorization = new AuthenticationHeaderValue("DGSIEM", Token);
        var okResponse = await http.SendAsync(ok);
        Assert.Equal(HttpStatusCode.OK, okResponse.StatusCode);
        Assert.Equal("""{"text":"Success","code":0}""", await okResponse.Content.ReadAsStringAsync());

        // Raw, gzipped, token in the query string.
        using var gz = new MemoryStream();
        await using (var zip = new GZipStream(gz, CompressionLevel.Fastest, leaveOpen: true))
        {
            await zip.WriteAsync("raw one\nraw two\n"u8.ToArray());
        }
        var raw = new ByteArrayContent(gz.ToArray());
        raw.Headers.ContentEncoding.Add("gzip");
        Assert.Equal(HttpStatusCode.OK, (await http.PostAsync($"/services/collector/raw?token={Token}&host=web01", raw)).StatusCode);

        // The scheme off-the-shelf HEC clients hardcode still works.
        var compat = new HttpRequestMessage(HttpMethod.Post, "/services/collector/event") { Content = new StringContent("""{"event":"compat"}""") };
        compat.Headers.Authorization = new AuthenticationHeaderValue("Splunk", Token);
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(compat)).StatusCode);

        // Bad body.
        var bad = new HttpRequestMessage(HttpMethod.Post, "/services/collector") { Content = new StringContent("""{"nope":1}""") };
        bad.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        var badResponse = await http.SendAsync(bad);
        Assert.Equal(HttpStatusCode.BadRequest, badResponse.StatusCode);
        Assert.Contains("\"code\":12", await badResponse.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        await cts.CancelAsync();
        await run;

        Assert.Equal(5, sent.Count);
        Assert.All(sent, e => Assert.Equal("hec", e.Input));
        Assert.All(sent, e => Assert.Equal("127.0.0.1", e.SourceAddress));
        Assert.All(sent, e => Assert.Equal("myapp", e.DatasetHint));
        Assert.Equal("""{"event":"raw two","host":"web01"}""", sent[3].Message);
    }

    // ---- Server: unwrapping ----------------------------------------------------------------

    [Fact]
    public void String_events_are_parsed_like_any_other_line()
    {
        var traefik = """{"ClientHost":"203.0.113.9","DownstreamStatus":200,"RequestHost":"app.example.com","RequestMethod":"GET","RequestPath":"/","RouterName":"r1"}""";
        var e = Parse(JsonSerializer.Serialize(new { @event = traefik, host = "edge-proxy", sourcetype = "traefik", time = 1762963200.25 }));
        Assert.Equal(TraefikParser.AccessDataset, e.EventDataset);
        Assert.Equal("203.0.113.9", e.SourceIp);
        Assert.Equal("edge-proxy", e.HostName);
        Assert.Equal("traefik", e.Fields["hec.sourcetype"]);
        Assert.Equal("10.0.1.50", e.ObserverIp);
    }

    [Fact]
    public void Plain_lines_take_the_hec_time_host_and_sourcetype()
    {
        var e = Parse("""{"event":"backup finished","time":"1762963200.5","host":"nas01","source":"/var/log/backup.log","sourcetype":"Backup:Job","index":"main"}""");
        Assert.Equal("backup.job", e.EventDataset);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1_762_963_200_500), e.Timestamp);
        Assert.Equal("nas01", e.HostName);
        Assert.Equal("backup finished", e.Message);
        Assert.Equal("/var/log/backup.log", e.Fields["hec.source"]);
        Assert.Equal("main", e.Fields["hec.index"]);

        // The input's dataset wins; then "hec" when nothing names one.
        Assert.Equal("myapp", Parse("""{"event":"x","sourcetype":"other"}""", "myapp").EventDataset);
        Assert.Equal("hec", Parse("""{"event":"x","sourcetype":"_json"}""").EventDataset);
    }

    [Fact]
    public void Syslog_lines_keep_their_own_time_and_host()
    {
        var e = Parse("""{"event":"<38>1 2026-11-12T15:00:00Z fw01 sshd 123 - - Accepted password for jdoe","host":"other","time":1762963200}""");
        Assert.Equal("fw01", e.HostName);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 15, 0, 0, TimeSpan.Zero), e.Timestamp);
        Assert.Equal("sshd", e.Fields["process.name"]);
        Assert.Equal("syslog", e.EventDataset); // no sourcetype: the line's own kind, not "hec"
    }

    [Fact]
    public void Docker_lines_are_unwrapped()
    {
        var e = Parse("""{"event":{"line":"GET /health 200","source":"stdout","tag":"web"},"host":"docker01","sourcetype":"docker:web"}""");
        Assert.Equal("GET /health 200", e.Message);
        Assert.Equal("docker.web", e.EventDataset);
        Assert.Equal("stdout", e.Fields["docker.stream"]);
        Assert.Equal("web", e.Fields["docker.tag"]);
    }

    [Fact]
    public void Object_events_are_flattened_onto_ecs()
    {
        var e = Parse("""
            {"event":{"msg":"login failed","level":"WARN","user":"jdoe","client_ip":"198.51.100.7","action":"login",
              "http":{"request":{"method":"POST"}},"tags":["a","b"],"nested":[{"x":1}],"bad key!":true,"count":3},
             "fields":{"env":"prod","host.name":"ignored-when-set"},"host":"api01","sourcetype":"api"}
            """);
        Assert.Equal("api", e.EventDataset);
        Assert.Equal("hec", e.EventModule);
        Assert.Equal("login failed", e.Message);
        Assert.Equal("warn", e.LogLevel);
        Assert.Equal("jdoe", e.UserName);
        Assert.Equal("198.51.100.7", e.SourceIp);
        Assert.Equal("login", e.EventAction);
        Assert.Equal("POST", e.Fields["http.request.method"]);
        Assert.Equal("a, b", e.Fields["tags"]);
        Assert.Equal("""[{"x":1}]""", e.Fields["nested"]);
        Assert.Equal("true", e.Fields["bad_key_"]);
        Assert.Equal("3", e.Fields["count"]);
        Assert.Equal("prod", e.Fields["env"]);
        Assert.Equal("api01", e.HostName);
        Assert.StartsWith("{\"msg\":\"login failed\"", e.Raw, StringComparison.Ordinal);
    }

    [Fact]
    public void Objects_without_a_message_keep_their_json_and_bad_ips_stay_fields()
    {
        var e = Parse("""{"event":{"temp":21.5,"ip":"not-an-ip"}}""");
        Assert.Equal("""{"temp":21.5,"ip":"not-an-ip"}""", e.Message);
        Assert.Equal(string.Empty, e.SourceIp);
        Assert.Equal("not-an-ip", e.Fields["ip"]);
    }

    [Fact]
    public void Millisecond_times_are_understood()
    {
        var e = Parse("""{"event":"x","time":1762963200123}""");
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1_762_963_200_123), e.Timestamp);
    }

    // ---- Server: config --------------------------------------------------------------------

    [Fact]
    public void Hec_inputs_need_good_tokens()
    {
        var ok = AdminService.ParseAndValidateConfig($$"""{"inputs":[{"type":"Hec","port":8088,"tokens":["{{Token}}"]}]}""");
        Assert.Equal(InputType.Hec, ok.Inputs[0].Type);

        Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"Hec","port":8088}]}"""));
        Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"Hec","port":8088,"tokens":["short"]}]}"""));
        Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig($$"""{"inputs":[{"type":"Hec","port":8088,"tokens":["{{Token}}","{{Token}}"]}]}"""));
        // HEC is TCP: it can't share a port with a TCP syslog input.
        Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig(
            $$"""{"inputs":[{"type":"Hec","port":5514,"tokens":["{{Token}}"]},{"type":"SyslogTcp","port":5514}]}"""));
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task WaitForHealthAsync(HttpClient http)
    {
        for (var i = 0; i < 100; i++)
        {
            try
            {
                if ((await http.GetAsync("/services/collector/health")).IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // Not listening yet.
            }
            await Task.Delay(50);
        }
        throw new TimeoutException("HEC listener didn't start.");
    }
}
