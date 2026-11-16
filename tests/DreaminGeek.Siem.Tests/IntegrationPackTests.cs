using System.Text.Json.Nodes;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Dashboards;
using DreaminGeek.Siem.Web.Integrations;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Tests;

public sealed class IntegrationPackTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("dgsiem-packs-").FullName;

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private PackCatalog Catalog() => new(Options.Create(new PackOptions { Directory = _folder }), new PipeParser(), NullLogger<PackCatalog>.Instance);

    private const string Minimal = """
        id: demo
        name: Demo
        version: 1
        category: Testing
        description: A test pack.
        setup:
          input: { type: InfluxDb, port: 8086, job: demo, tokens: ["{{token}}"] }
          steps:
            - "Token: {{token}} on port {{port}}, `code` and **bold** <b>"
        receiving:
          search: '| mstats count(demo_value) as n | where n > 0'
        dashboards:
          - key: main
            name: Demo dashboard
            panels:
              - { title: Count, kind: stat, search: 'dataset=demo | stats count()' }
              - { title: Over time, kind: timeline, search: '| mstats avg(demo_value) by host span=5m' }
              - { title: Top, kind: bars, search: 'dataset=demo | top limit=5 host' }
              - { title: Table, kind: table, w: 12, search: 'dataset=demo | stats count() by host' }
        alerts:
          - key: quiet
            name: Demo went quiet
            search: '| mstats count(demo_value) as n | where n > 0'
            condition: below
            threshold: 1
            severity: high
          - key: busy
            name: Demo busy
            search: '| mstats avg(demo_value) as v by host | where v > 5'
            trigger: per-result
            suppressBy: host
        """;

    [Fact]
    public void The_built_in_proxmox_pack_loads_cleanly()
    {
        var catalog = Catalog();
        Assert.Empty(catalog.Problems);
        var pack = Assert.IsType<IntegrationPack>(catalog.Find("proxmox"));
        Assert.True(pack.BuiltIn);
        Assert.NotEmpty(pack.Dashboards);
        Assert.NotEmpty(pack.Alerts);

        // Numbers stay numbers in the agent input; the token is filled in.
        var input = JsonNode.Parse(PackContent.InputJson(pack, "abc_DEF-123")!)!;
        Assert.Equal("InfluxDb", (string?)input["type"]);
        Assert.Equal(8086, (int)input["port"]!);
        Assert.Equal("abc_DEF-123", (string?)input["tokens"]![0]);
        Assert.Equal("8086", PackContent.Port(pack));
    }

    [Fact]
    public void Packs_from_the_folder_load_and_broken_ones_are_reported()
    {
        File.WriteAllText(Path.Combine(_folder, "demo.yaml"), Minimal);
        Directory.CreateDirectory(Path.Combine(_folder, "broken"));
        File.WriteAllText(Path.Combine(_folder, "broken", "pack.yaml"), "id: broken\nname: [unclosed");
        File.WriteAllText(Path.Combine(_folder, "dupe.yaml"), Minimal.Replace("name: Demo\n", "name: Demo again\n", StringComparison.Ordinal));

        var catalog = Catalog();
        var demo = Assert.IsType<IntegrationPack>(catalog.Find("demo"));
        Assert.False(demo.BuiltIn);
        Assert.Equal(2, catalog.Problems.Count);
        Assert.Contains(catalog.Problems, p => p.Source.EndsWith("pack.yaml", StringComparison.Ordinal) && p.Message.StartsWith("Line", StringComparison.Ordinal));
        Assert.Contains(catalog.Problems, p => p.Message.Contains("already has the id", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("search: 'dataset=demo | stats count()'", "search: 'dataset=demo | stats bogus('", "panel \"Count\"")]
    [InlineData("search: 'dataset=demo | stats count()'", "search: 'dataset=demo host={{tenant}} | stats count()'", "only work in the setup")]
    [InlineData("kind: stat", "kind: sparkle", "isn't one of timeline")]
    [InlineData("key: busy", "key: quiet", "its own key")]
    [InlineData("severity: high", "severity: dire", "isn't one of low")]
    [InlineData("condition: below", "condition: sideways", "isn't one of any")]
    [InlineData("tokens: [\"{{token}}\"]", "tokens: [\"x\"]", "setup input")]
    [InlineData("id: demo", "id: Demo Pack", "isn't a pack id")]
    public void Mistakes_are_caught_when_the_pack_is_read(string from, string to, string message)
    {
        var yaml = Minimal.Replace(from, to, StringComparison.Ordinal);
        Assert.NotEqual(Minimal, yaml);
        var pack = PackContent.Parse(yaml);
        var ex = Assert.Throws<PackException>(() => PackCatalog.Validate(pack, new PipeParser()));
        Assert.Contains(message, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Panels_flow_across_the_grid()
    {
        var pack = PackContent.Parse(Minimal);
        var panels = PackContent.Panels(pack.Dashboards[0]);
        Assert.Equal([(0, 0), (3, 0), (0, 4), (0, 8)], panels.Select(p => (p.X, p.Y)));
        Assert.Equal(["main-0", "main-1", "main-2", "main-3"], panels.Select(p => p.Id));
        Assert.Equal(PanelKind.Stat, panels[0].Kind);
        Assert.Equal(12, panels[3].W);
    }

    [Fact]
    public void Steps_are_encoded_and_filled_in()
    {
        var html = PackContent.StepHtml(PackContent.Parse(Minimal).Setup.Steps[0], new Dictionary<string, string> { ["token"] = "t<1>", ["port"] = "8086" });
        Assert.Equal("Token: <code class=\"dg-pack-value\">t&lt;1&gt;</code> on port <code class=\"dg-pack-value\">8086</code>, <code>code</code> and <strong>bold</strong> &lt;b&gt;", html);
    }

    [Fact]
    public void Tokens_are_long_and_safe_for_every_input()
    {
        var token = IntegrationService.NewToken();
        Assert.Equal(43, token.Length);
        Assert.Matches("^[A-Za-z0-9_-]+$", token);
        Assert.NotEqual(token, IntegrationService.NewToken());
        Assert.True(IntegrationService.NeedsToken(PackContent.Parse(Minimal)));
    }

    private static SiemDbContext Db(string name) =>
        new(new DbContextOptionsBuilder<SiemDbContext>().UseInMemoryDatabase(name).Options);

    private static IntegrationPack Pack(string yaml)
    {
        var pack = PackContent.Parse(yaml);
        PackCatalog.Validate(pack, new PipeParser());
        return pack;
    }

    [Fact]
    public async Task Installing_creates_dashboards_and_switched_off_alerts_once()
    {
        var name = Guid.NewGuid().ToString();
        await using (var db = Db(name))
        {
            db.Dashboards.Add(new Dashboard { Id = Guid.NewGuid(), Name = "Demo dashboard", PackId = "other" }); // another pack's, same name
            await db.SaveChangesAsync();
            var report = await IntegrationService.SyncAsync(db, Pack(Minimal), Guid.NewGuid(), CancellationToken.None);
            Assert.Equal(3, report.Created);
        }
        await using (var db = Db(name))
        {
            var dashboard = await db.Dashboards.SingleAsync(d => d.PackId == "demo");
            Assert.Equal("Demo dashboard (Demo)", dashboard.Name);
            Assert.Equal(PackContent.Hash(dashboard), dashboard.PackHash);
            var alerts = await db.AlertRules.Where(a => a.PackId == "demo").ToListAsync();
            Assert.Equal(2, alerts.Count);
            Assert.All(alerts, a => Assert.False(a.Enabled));
            Assert.All(alerts, a => Assert.Equal(PackContent.Hash(a), a.PackHash));
            var quiet = alerts.Single(a => a.PackItem == "quiet");
            Assert.Equal(AlertCondition.CountLessThan, quiet.Condition);
            Assert.Equal("-15m", quiet.TimeRange);
            Assert.Null(quiet.TenantId);

            // Again: nothing to do.
            var again = await IntegrationService.SyncAsync(db, Pack(Minimal), Guid.NewGuid(), CancellationToken.None);
            Assert.Equal((0, 0, 0), (again.Created, again.Updated, again.Removed));
            Assert.Empty(again.KeptEdited);
            Assert.Equal("Demo dashboard (Demo)", (await db.Dashboards.SingleAsync(d => d.PackId == "demo")).Name);
        }
    }

    [Fact]
    public async Task Updates_refresh_untouched_items_and_leave_edited_ones_alone()
    {
        var name = Guid.NewGuid().ToString();
        await using (var db = Db(name))
        {
            await IntegrationService.SyncAsync(db, Pack(Minimal), Guid.Empty, CancellationToken.None);
            // Turning an alert on and adding a recipient isn't an edit; changing the other's search is.
            var quiet = await db.AlertRules.SingleAsync(a => a.PackItem == "quiet");
            quiet.Enabled = true;
            quiet.EmailTo = "ops@example.com";
            var busy = await db.AlertRules.SingleAsync(a => a.PackItem == "busy");
            busy.Query += " | where v > 6";
            await db.SaveChangesAsync();
        }

        var v2 = Minimal
            .Replace("version: 1", "version: 2", StringComparison.Ordinal)
            .Replace("severity: high", "severity: critical", StringComparison.Ordinal)
            .Replace("trigger: per-result", "trigger: once", StringComparison.Ordinal)
            .Replace("      - { title: Top, kind: bars, search: 'dataset=demo | top limit=5 host' }\n", "", StringComparison.Ordinal);
        await using (var db = Db(name))
        {
            var report = await IntegrationService.SyncAsync(db, Pack(v2), Guid.Empty, CancellationToken.None);
            Assert.Equal(0, report.Created);
            Assert.Equal(2, report.Updated); // the dashboard (one panel fewer) and "quiet"
            Assert.Equal(["Demo busy"], report.KeptEdited);

            var quiet = await db.AlertRules.SingleAsync(a => a.PackItem == "quiet");
            Assert.Equal(AlertSeverity.Critical, quiet.Severity);
            Assert.True(quiet.Enabled);
            Assert.Equal("ops@example.com", quiet.EmailTo);
            var busy = await db.AlertRules.SingleAsync(a => a.PackItem == "busy");
            Assert.Equal(AlertTrigger.PerResult, busy.Trigger); // left as edited
            Assert.Equal(3, PanelJson.Deserialize((await db.Dashboards.SingleAsync(d => d.PackId == "demo")).LayoutJson).Count);
        }

        // A version without the alerts: the untouched one goes, the edited one becomes your own.
        var v3 = v2[..v2.IndexOf("alerts:", StringComparison.Ordinal)].Replace("version: 2", "version: 3", StringComparison.Ordinal);
        await using (var db = Db(name))
        {
            var report = await IntegrationService.SyncAsync(db, Pack(v3), Guid.Empty, CancellationToken.None);
            Assert.Equal(1, report.Removed);
            var left = await db.AlertRules.SingleAsync();
            Assert.Equal("Demo busy", left.Name);
            Assert.Null(left.PackId);
        }
    }

    [Fact]
    public async Task Pack_alerts_run_only_for_tenants_the_pack_is_on_for()
    {
        await using var db = Db(Guid.NewGuid().ToString());
        var acme = new Tenant { Id = Guid.NewGuid(), Slug = "acme", Name = "Acme" };
        var globex = new Tenant { Id = Guid.NewGuid(), Slug = "globex", Name = "Globex" };
        db.Tenants.AddRange(acme, globex);
        db.TenantPacks.Add(new TenantPack { TenantId = acme.Id, PackId = "proxmox" });
        await db.SaveChangesAsync();

        async Task<string[]> For(AlertRule rule) =>
            (await DreaminGeek.Siem.Alerting.AlertRunner.TenantsAsync(db, rule, CancellationToken.None)).Select(t => t.Slug).ToArray();

        Assert.Equal(["acme", "globex"], await For(new AlertRule { Name = "mine", Query = "x" }));
        Assert.Equal(["acme"], await For(new AlertRule { Name = "pack", Query = "x", PackId = "proxmox" }));
        Assert.Empty(await For(new AlertRule { Name = "pack, narrowed", Query = "x", PackId = "proxmox", TenantId = globex.Id }));
        Assert.Empty(await For(new AlertRule { Name = "other pack", Query = "x", PackId = "unifi" }));
    }

    [Fact]
    public void Built_in_packs_load_and_their_alerts_suppress_by_result_columns()
    {
        var catalog = Catalog();
        Assert.Empty(catalog.Problems);
        Assert.Equal(["authentik", "crowdsec", "pangolin", "pbx", "proxmox", "unifi", "windows"], catalog.Packs.Select(p => p.Id).Order(StringComparer.Ordinal));
        var now = DateTimeOffset.UtcNow;
        foreach (var alert in catalog.Packs.SelectMany(p => p.Alerts))
        {
            var compiled = new ClickHouseCompiler("dgsiem").Compile(new PipeParser().Parse(alert.Search),
                new QueryRequest(alert.Search, now.AddHours(-1), now, ["dg"]));
            Assert.Contains("tenant_id IN", compiled.Sql, StringComparison.Ordinal);
            // Repeats are recognised by these fields, so they must be columns of the result.
            foreach (var key in (alert.SuppressBy ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                Assert.True(compiled.Columns.Contains(key), $"{alert.Name}: suppressBy {key} isn't one of {string.Join(", ", compiled.Columns)}");
            }
        }
    }

    [Fact]
    public async Task Installing_adopts_dashboards_and_alerts_of_yours_with_the_same_names()
    {
        var pack = Pack(Minimal);
        await using var db = Db(Guid.NewGuid().ToString());
        // As added from the old ready-made lists: same definition, random panel ids, switched on with a recipient.
        var mine = new Dashboard { Id = Guid.NewGuid(), Name = "Demo dashboard", Description = "x", TimeRange = "-24h" };
        var panels = PackContent.Panels(pack.Dashboards[0]);
        panels.ForEach(p => p.Id = Guid.NewGuid().ToString("N")[..10]);
        mine.LayoutJson = PanelJson.Serialize(panels);
        mine.Description = null;
        var quiet = new AlertRule
        {
            Id = Guid.NewGuid(), Name = "Demo went quiet", Query = pack.Alerts[0].Search, TimeRange = "-15m", Schedule = "*/5 * * * *",
            Condition = AlertCondition.CountLessThan, Threshold = 1, Severity = AlertSeverity.High, Enabled = true, EmailTo = "ops@example.com",
            SuppressFor = TimeSpan.FromMinutes(60),
        };
        var busy = new AlertRule { Id = Guid.NewGuid(), Name = "Demo busy", Query = "dataset=demo | stats count()", Enabled = true };
        db.Dashboards.Add(mine);
        db.AlertRules.AddRange(quiet, busy);
        await db.SaveChangesAsync();

        var report = await IntegrationService.SyncAsync(db, pack, Guid.Empty, CancellationToken.None);
        Assert.Equal(0, report.Created);
        Assert.Equal(["Demo dashboard", "Demo went quiet", "Demo busy"], report.Adopted);
        Assert.Equal(3, await db.Dashboards.CountAsync() + await db.AlertRules.CountAsync());

        Assert.True(PackContent.Untouched(await db.Dashboards.SingleAsync()));      // same as the pack's
        var adoptedQuiet = await db.AlertRules.SingleAsync(a => a.Name == "Demo went quiet");
        Assert.True(PackContent.Untouched(adoptedQuiet));
        Assert.True(adoptedQuiet.Enabled);
        Assert.Equal("ops@example.com", adoptedQuiet.EmailTo);
        Assert.False(PackContent.Untouched(await db.AlertRules.SingleAsync(a => a.Name == "Demo busy"))); // differs: kept as edited

        var again = await IntegrationService.SyncAsync(db, pack, Guid.Empty, CancellationToken.None);
        Assert.Equal((0, 0, 0), (again.Created, again.Updated, again.Removed));
        Assert.Equal(["Demo busy"], again.KeptEdited);
        Assert.Empty(again.Adopted!);
    }

    [Fact]
    public void Dashboards_written_by_the_first_version_still_count_as_untouched()
    {
        // 0.7.0 fingerprinted the layout with its panel ids.
        var d = new Dashboard { Name = "Demo dashboard", TimeRange = "-24h", LayoutJson = PanelJson.Serialize(PackContent.Panels(Pack(Minimal).Dashboards[0])) };
        d.PackHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            string.Join('\u001f', d.Name, "", d.TimeRange, PanelJson.Serialize(PanelJson.Deserialize(d.LayoutJson))))))[..32];
        Assert.True(PackContent.Untouched(d));
        d.TimeRange = "-7d";
        Assert.False(PackContent.Untouched(d));
    }

    [Fact]
    public void Panels_with_a_position_keep_it()
    {
        var pack = Pack(Minimal.Replace("{ title: Top, kind: bars,", "{ title: Top, kind: bars, x: 8, y: 20,", StringComparison.Ordinal));
        var top = PackContent.Panels(pack.Dashboards[0]).Single(p => p.Title == "Top");
        Assert.Equal((8, 20), (top.X, top.Y));
        Assert.Throws<PackException>(() => Pack(Minimal.Replace("{ title: Top, kind: bars,", "{ title: Top, kind: bars, x: 3,", StringComparison.Ordinal)));
    }
}
