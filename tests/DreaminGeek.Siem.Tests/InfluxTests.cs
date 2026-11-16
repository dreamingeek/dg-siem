using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Ingest.Metrics;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Logging.Abstractions;

namespace DreaminGeek.Siem.Tests;

public class InfluxLineProtocolTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);

    private static List<MetricSample> Parse(string lines, string precision = "auto") =>
        InfluxLineProtocol.Parse(new RawEnvelope(At, "influx:proxmox", "192.0.2.10", MetricPush.HeaderPrefix + precision + "\n" + lines), "acme");

    // The shape of what Proxmox VE's metric server sends (VM status with string fields, node CPU, a NIC).
    private const string Proxmox = """
        system,object=qemu,vmid=101,nodename=pve1,host=web01 uptime=86400i,name="web01",status="running",cpu=0.0213,cpus=2i,maxmem=4294967296i,mem=1073741824i,template=0i 1763208000000000000
        cpustat,object=nodes,host=pve1 cpu=0.084,iowait=0.002,user=1234567i 1763208000000000000
        nics,object=nodes,host=pve1,instance=vmbr0 receive=987654321i,transmit=123456789i 1763208000000000000
        """;

    [Fact]
    public void Reads_proxmox_style_lines_into_measurement_field_metrics()
    {
        var samples = Parse(Proxmox);
        MetricSample One(string name) => samples.Single(s => s.Name == name);

        Assert.Equal(["system_cpu", "system_cpus", "system_maxmem", "system_mem", "system_template", "system_uptime"],
            samples.Where(s => s.Name.StartsWith("system_", StringComparison.Ordinal)).Select(s => s.Name).Order(StringComparer.Ordinal));
        var cpu = One("system_cpu");
        Assert.Equal(0.0213, cpu.Value);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1763208000), cpu.Timestamp);
        Assert.Equal("101", cpu.Labels["vmid"]);
        Assert.Equal("web01", cpu.Labels["host"]);
        Assert.Equal("proxmox", cpu.Labels["job"]);
        Assert.Equal("192.0.2.10", cpu.Labels["instance"]);
        Assert.Equal(4294967296, One("system_maxmem").Value);
        Assert.Equal(0.084, One("cpustat_cpu").Value);

        // A NIC's own "instance" tag is kept as exported_instance; ours is the sender.
        var rx = One("nics_receive");
        Assert.Equal("vmbr0", rx.Labels["exported_instance"]);
        Assert.Equal("192.0.2.10", rx.Labels["instance"]);
        Assert.All(samples, s => Assert.Equal("acme", s.TenantId));
    }

    [Fact]
    public void Handles_escapes_strings_booleans_and_comments()
    {
        var samples = Parse("""
            # a comment
            disk\ io,dev=sda\,1,path=C:\\x read=5u,ok=true,note="a, b=c \"quoted\"",down=F
            weather temp=-3.5e1
            broken line
            no_fields,tag=x
            """);
        var read = samples.Single(s => s.Name == "disk_io_read");
        Assert.Equal(5, read.Value);
        Assert.Equal("sda,1", read.Labels["dev"]);
        Assert.Equal(@"C:\x", read.Labels["path"]);
        Assert.Equal(1, samples.Single(s => s.Name == "disk_io_ok").Value);
        Assert.Equal(0, samples.Single(s => s.Name == "disk_io_down").Value);
        Assert.DoesNotContain(samples, s => s.Name == "disk_io_note");
        Assert.Equal(-35, samples.Single(s => s.Name == "weather_temp").Value);
        Assert.Equal(At, samples.Single(s => s.Name == "weather_temp").Timestamp); // no timestamp: when it arrived
        Assert.Equal(4, samples.Count);
    }

    [Theory]
    [InlineData(1763208000L, "auto")]
    [InlineData(1763208000000L, "auto")]
    [InlineData(1763208000000000L, "auto")]
    [InlineData(1763208000000000000L, "auto")]
    [InlineData(1763208000L, "s")]
    [InlineData(1763208000000L, "ms")]
    [InlineData(1763208000000000L, "us")]
    [InlineData(1763208000000000000L, "ns")]
    public void Timestamps_follow_the_precision_or_their_size(long value, string precision) =>
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1763208000), InfluxLineProtocol.Timestamp(value, precision));
}

public class InfluxInputTests
{
    private const string Token = "pve-metrics-token-123";

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    [Fact]
    public async Task Accepts_v2_and_v1_writes_with_the_token()
    {
        var port = FreePort();
        var sent = new List<RawEnvelope>();
        var config = new InputConfig { Type = InputType.InfluxDb, BindAddress = "127.0.0.1", Port = port, Tokens = [Token], Job = "proxmox" };
        var input = new InfluxHttpInput(config, null!, null, NullLogger.Instance) { Emit = e => { lock (sent) { sent.Add(e); } return true; } };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = input.RunAsync(cts.Token);
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
        for (var i = 0; i < 100; i++)
        {
            try
            {
                if ((await http.GetAsync("/ping")).StatusCode == HttpStatusCode.NoContent)
                {
                    break;
                }
            }
            catch (HttpRequestException)
            {
            }
            await Task.Delay(50);
        }

        // Proxmox: POST /api/v2/write?org=proxmox&bucket=proxmox, Authorization: Token ...
        var v2 = new HttpRequestMessage(HttpMethod.Post, "/api/v2/write?org=proxmox&bucket=proxmox") { Content = new StringContent("cpustat,host=pve1 cpu=0.5 1763208000000000000") };
        v2.Headers.Authorization = new AuthenticationHeaderValue("Token", Token);
        Assert.Equal(HttpStatusCode.NoContent, (await http.SendAsync(v2)).StatusCode);

        // v1 with the token as password and seconds precision.
        Assert.Equal(HttpStatusCode.NoContent, (await http.PostAsync($"/write?db=x&p={Token}&precision=s", new StringContent("cpustat,host=pve2 cpu=0.25 1763208000"))).StatusCode);

        // Without or with a wrong token.
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.PostAsync("/api/v2/write", new StringContent("x v=1"))).StatusCode);
        var wrong = new HttpRequestMessage(HttpMethod.Post, "/api/v2/write") { Content = new StringContent("x v=1") };
        wrong.Headers.Authorization = new AuthenticationHeaderValue("Token", "nope-nope-nope");
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(wrong)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsync($"/write?p={Token}&precision=fortnight", new StringContent("x v=1"))).StatusCode);

        await cts.CancelAsync();
        await run;

        Assert.Equal(2, sent.Count);
        Assert.All(sent, e => Assert.Equal("influx:proxmox", e.Input));
        Assert.Equal("127.0.0.1", sent[0].SourceAddress);
        var samples = sent.SelectMany(e => InfluxLineProtocol.Parse(e, "acme")).ToList();
        Assert.Equal([0.5, 0.25], samples.Select(s => s.Value));
        Assert.All(samples, s => Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1763208000), s.Timestamp));
    }

    [Fact]
    public void Config_is_checked_when_saved()
    {
        var config = AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"InfluxDb","port":8086,"job":"proxmox","tokens":["pve-metrics-token"]},{"type":"InfluxDbUdp","port":8089}]}""");
        Assert.Contains("need agent 0.7.0", Assert.Throws<AdminException>(() => AdminService.RequireAgentSupports(config, "0.6.0")).Message, StringComparison.Ordinal);
        AdminService.RequireAgentSupports(config, "0.7.0");
        Assert.Contains("can't check tokens", Assert.Throws<AdminException>(() =>
            AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"InfluxDbUdp","port":8089,"tokens":["abcdefghij"]}]}""")).Message, StringComparison.Ordinal);
        Assert.Contains("Two inputs use udp port 514", Assert.Throws<AdminException>(() =>
            AdminService.ParseAndValidateConfig("""{"inputs":[{"type":"InfluxDbUdp","port":514},{"type":"SyslogUdp","port":514}]}""")).Message, StringComparison.Ordinal);
    }
}
