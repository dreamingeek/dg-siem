using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;

namespace DreaminGeek.Siem.Tests;

public class ParserRegistryTests
{
    [Fact]
    public void Unparseable_lines_are_kept_as_raw_events()
    {
        var registry = new ParserRegistry([new SyslogParser()]);
        var env = new RawEnvelope(DateTimeOffset.UtcNow, "file", null, "just some text", "app.log");

        var e = registry.Parse(env, "acme");

        Assert.Equal("acme", e.TenantId);
        Assert.Equal("app.log", e.EventDataset);
        Assert.Equal("just some text", e.Raw);
        Assert.Equal("just some text", e.Message);
    }
}
