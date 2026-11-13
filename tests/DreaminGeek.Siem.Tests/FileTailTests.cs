using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Logging.Abstractions;

namespace DreaminGeek.Siem.Tests;

public sealed class FileTailTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("dgsiem-tail-").FullName;
    private readonly List<RawEnvelope> _sent = [];
    private DateTimeOffset _now = new(2026, 11, 12, 16, 0, 0, TimeSpan.Zero);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string P(string name) => Path.Combine(_dir, name);

    private FileTailInput Tail(InputConfig config, FilePositions? positions = null) =>
        new(config, null!, positions ?? new FilePositions(P("positions.json")), NullLogger.Instance) { Emit = _sent.Add, Now = () => _now };

    private InputConfig Config(string pattern, bool fromBeginning = false, MultilineMode multiline = MultilineMode.None, string? app = null) =>
        new() { Type = InputType.File, Paths = [P(pattern)], FromBeginning = fromBeginning, Multiline = multiline, App = app };

    private List<string> Lines() => _sent.Select(e => e.Message[(e.Message.IndexOf(" - - - ", StringComparison.Ordinal) + 7)..]).ToList();

    [Fact]
    public void ExistingFilesStartAtTheEnd()
    {
        File.WriteAllText(P("app.log"), "old line 1\nold line 2\n");
        var tail = Tail(Config("app.log"));
        tail.PollOnce();
        Assert.Empty(_sent);

        File.AppendAllText(P("app.log"), "new line\n");
        tail.PollOnce();
        Assert.Equal(["new line"], Lines());
        Assert.Equal($"file:{P("app.log")}", _sent[0].Input);
    }

    [Fact]
    public void FromBeginningReadsWhatsThere()
    {
        File.WriteAllText(P("app.log"), "one\r\ntwo\n");
        var tail = Tail(Config("app.log", fromBeginning: true));
        tail.PollOnce();
        Assert.Equal(["one", "two"], Lines());
    }

    [Fact]
    public void PartialLinesWaitForTheirNewline()
    {
        File.WriteAllText(P("app.log"), "");
        var tail = Tail(Config("app.log"));
        tail.PollOnce();
        File.AppendAllText(P("app.log"), "half a li");
        tail.PollOnce();
        Assert.Empty(_sent);
        File.AppendAllText(P("app.log"), "ne\nnext\n");
        tail.PollOnce();
        Assert.Equal(["half a line", "next"], Lines());
    }

    [Fact]
    public void RotationByRenameDrainsTheOldFileThenReadsTheNewOne()
    {
        File.WriteAllText(P("app.log"), new string('x', 300) + "\n");
        var tail = Tail(Config("app.log"));
        tail.PollOnce();
        File.AppendAllText(P("app.log"), "before rotate\n");
        // logrotate: rename, the app writes one more line to its old handle, then a new file appears.
        File.Move(P("app.log"), P("app.log.1"));
        File.AppendAllText(P("app.log.1"), "late write to old file\n");
        File.WriteAllText(P("app.log"), "first line of new file\n");
        tail.PollOnce();
        Assert.Equal(["before rotate", "late write to old file", "first line of new file"], Lines());
    }

    [Fact]
    public void CopyTruncateStartsOverAtZero()
    {
        File.WriteAllText(P("app.log"), "a\nb\nc\n");
        var tail = Tail(Config("app.log"));
        tail.PollOnce();
        File.WriteAllText(P("app.log"), "");
        tail.PollOnce();
        File.AppendAllText(P("app.log"), "after truncate\n");
        tail.PollOnce();
        Assert.Equal(["after truncate"], Lines());
    }

    [Fact]
    public void RestartResumesWithoutDuplicates()
    {
        File.WriteAllText(P("app.log"), "");
        var positions = new FilePositions(P("positions.json"));
        var first = Tail(Config("app.log"), positions);
        first.PollOnce();
        File.AppendAllText(P("app.log"), "line 1\n");
        first.PollOnce();
        positions.Save();

        File.AppendAllText(P("app.log"), "written while stopped\n");
        var second = Tail(Config("app.log"), new FilePositions(P("positions.json")));
        second.PollOnce();
        Assert.Equal(["line 1", "written while stopped"], Lines());
    }

    [Fact]
    public void IndentedLinesJoinTheEventAbove()
    {
        File.WriteAllText(P("app.log"), "");
        var tail = Tail(Config("app.log", multiline: MultilineMode.Indented));
        tail.PollOnce();
        File.AppendAllText(P("app.log"), "Exception: boom\n   at A.B()\n\tat C.D()\nnext event\n");
        tail.PollOnce();
        Assert.Equal(["Exception: boom\n   at A.B()\n\tat C.D()"], Lines());
        _now = _now.AddSeconds(5); // the last event is sent once the file goes quiet
        tail.PollOnce();
        Assert.Equal("next event", Lines()[^1]);
    }

    [Fact]
    public void PatternMultilineJoinsAsteriskSipPacketsWithLocalTime()
    {
        File.WriteAllText(P("full"), "");
        var config = new InputConfig
        {
            Type = InputType.File, Paths = [P("full")], App = "asterisk",
            Multiline = MultilineMode.Pattern, MultilineStart = @"^\[\d{4}-",
        };
        var central = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
        _now = new DateTimeOffset(2026, 11, 12, 16, 31, 17, TimeSpan.Zero);
        var tail = new FileTailInput(config, null!, new FilePositions(P("positions.json")), NullLogger.Instance) { Emit = _sent.Add, Now = () => _now, Zone = central };
        tail.PollOnce();
        File.AppendAllText(P("full"),
            "[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip_logger.c: <--- Transmitting SIP response (430 bytes) to UDP:216.160.83.56:9505 --->\n" +
            "SIP/2.0 200 OK\nCall-ID: 1bc9d842\nCSeq: 24854 REGISTER\nContent-Length:  0\n\n\n" +
            "[2026-11-12 10:31:16] VERBOSE[1554] res_pjsip/pjsip_configuration.c: Endpoint 114 is now Reachable\n");
        tail.PollOnce();
        _now = _now.AddSeconds(5);
        tail.PollOnce();

        Assert.Equal(2, _sent.Count);
        Assert.Contains("2026-11-12T10:31:17.000000-06:00", _sent[0].Message, StringComparison.Ordinal);
        Assert.EndsWith("SIP/2.0 200 OK\nCall-ID: 1bc9d842\nCSeq: 24854 REGISTER\nContent-Length:  0", _sent[0].Message, StringComparison.Ordinal);

        var registry = new ParserRegistry([new AsteriskParser(), new SyslogParser()]);
        var packet = registry.Parse(_sent[0], "acme");
        Assert.Equal("asterisk.sip", packet.EventDataset);
        Assert.Equal("1bc9d842", packet.Fields["sip.call_id"]);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 16, 31, 16, TimeSpan.Zero), packet.Timestamp);
        Assert.Equal("endpoint-reachable", registry.Parse(_sent[1], "acme").EventAction);
    }

    [Fact]
    public void WildcardsMatchFilesButNotCompressedRotations()
    {
        File.WriteAllText(P("a.log"), "");
        File.WriteAllText(P("b.log"), "");
        File.WriteAllText(P("c.log.gz"), "");
        File.WriteAllText(P("notes.txt"), "");
        Assert.Equal([P("a.log"), P("b.log")], FileTailInput.Expand([P("*.log")]));
        Assert.Empty(FileTailInput.Expand([P("missing.log"), "/no/such/dir/*.log"]));
    }

    [Fact]
    public void OverlongLinesAreCut()
    {
        File.WriteAllText(P("app.log"), "");
        var tail = Tail(Config("app.log"));
        tail.PollOnce();
        File.AppendAllText(P("app.log"), new string('y', 100_000) + "\nshort\n");
        tail.PollOnce();
        Assert.Equal(FileTailInput.MaxLineBytes, Lines()[0].Length);
        Assert.Equal("short", Lines()[1]);
    }

    [Fact]
    public void WrappedLinesParseLikeForwardedSyslog()
    {
        File.WriteAllText(P("access.log"), "");
        var tail = Tail(Config("access.log", app: "traefik-access"));
        tail.PollOnce();
        File.AppendAllText(P("access.log"), """{"ClientHost":"216.160.83.56","ClientPort":"1","DownstreamStatus":200,"RequestHost":"x.example.com","RequestMethod":"GET","RequestPath":"/","StartUTC":"2026-11-12T05:04:22Z"}""" + "\n");
        tail.PollOnce();

        var registry = new ParserRegistry([new TraefikParser(), new SyslogParser()]);
        var e = registry.Parse(Assert.Single(_sent), "dg");
        Assert.Equal("traefik.access", e.EventDataset);
        Assert.Equal("traefik-access", e.Fields["process.name"]);
        Assert.Equal(P("access.log"), e.Fields["log.file.path"]);
        Assert.Equal(Environment.MachineName, e.HostName);

        var plain = registry.Parse(new RawEnvelope(_now, "file:/var/log/app.log", null, "<14>1 2026-11-12T16:00:00Z host app - - - hello world"), "dg");
        Assert.Equal("hello world", plain.Message);
        Assert.Equal("/var/log/app.log", plain.Fields["log.file.path"]);
    }

    [Theory]
    [InlineData("""{"inputs":[{"type":"File","paths":["/var/log/nginx/*.log"],"app":"nginx"}]}""", null)]
    [InlineData("""{"inputs":[{"type":"File","paths":["C:\\logs\\app.log"]}]}""", null)]
    [InlineData("""{"inputs":[{"type":"File"}]}""", "needs \"paths\"")]
    [InlineData("""{"inputs":[{"type":"File","paths":["logs/app.log"]}]}""", "must be absolute")]
    [InlineData("""{"inputs":[{"type":"File","paths":["/var/log/*/app.log"]}]}""", "only allowed in the file name")]
    [InlineData("""{"inputs":[{"type":"File","paths":["/var/log/"]}]}""", "is a folder")]
    [InlineData("""{"inputs":[{"type":"File","paths":["/x.log"],"app":"has space"}]}""", "no spaces")]
    [InlineData("""{"inputs":[{"type":"File","paths":["/a.log"]},{"type":"File","paths":["/b.log"]},{"type":"SyslogUdp","port":514}]}""", null)]
    [InlineData("""{"inputs":[{"type":"File","paths":["/var/log/asterisk/full"],"multiline":"Pattern","multilineStart":"^\\[\\d{4}-"}]}""", null)]
    [InlineData("""{"inputs":[{"type":"File","paths":["/var/log/asterisk/full"],"multiline":"Pattern"}]}""", "needs \"multilineStart\"")]
    [InlineData("""{"inputs":[{"type":"File","paths":["/var/log/asterisk/full"],"multiline":"Pattern","multilineStart":"[unclosed"}]}""", "isn't a valid regular expression")]
    public void FileInputConfigIsValidated(string json, string? error)
    {
        if (error is null)
        {
            AdminService.ParseAndValidateConfig(json);
        }
        else
        {
            Assert.Contains(error, Assert.Throws<AdminException>(() => AdminService.ParseAndValidateConfig(json)).Message, StringComparison.Ordinal);
        }
    }
}
