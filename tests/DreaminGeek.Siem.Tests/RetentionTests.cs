using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Tests;

public sealed class RetentionTests
{
    private static RetentionPolicy Policy(int defaultDays, params RetentionRule[] rules)
    {
        var p = new RetentionPolicy();
        p.Update(new RetentionSettings(defaultDays, rules));
        return p;
    }

    [Fact]
    public void Most_specific_rule_wins()
    {
        var p = Policy(120,
            new(null, "*", 90),
            new(null, "unifi.*", 30),
            new(null, "unifi.firewall", 14),
            new(null, "windows.security", 365),
            new("globex", "*", 60),
            new("globex", "windows.*", 180));

        Assert.Equal(14, p.DaysFor("dg", "unifi.firewall"));      // exact beats prefix
        Assert.Equal(30, p.DaysFor("dg", "unifi.vpn"));           // prefix beats *
        Assert.Equal(90, p.DaysFor("dg", "traefik.access"));      // * beats the default
        Assert.Equal(365, p.DaysFor("acme", "windows.security"));
        Assert.Equal(180, p.DaysFor("globex", "windows.security"));  // a tenant's own rule beats an all-tenant one
        Assert.Equal(60, p.DaysFor("globex", "unifi.firewall"));
        Assert.Equal(60, p.DaysFor("Globex", "anything"));           // case-insensitive
        Assert.Equal(120, Policy(120).DaysFor("dg", "x"));
    }

    [Fact]
    public void Suggested_rules_keep_security_a_year_and_noise_a_month()
    {
        var p = new RetentionPolicy(); // starts with the suggested rules
        Assert.Equal(365, p.DaysFor("dg", "windows.security"));
        Assert.Equal(365, p.DaysFor("acme", "asterisk.security"));
        Assert.Equal(30, p.DaysFor("dg", "unifi.firewall"));
        Assert.Equal(30, p.DaysFor("dg", "asterisk.sip"));
        Assert.Equal(120, p.DaysFor("dg", "windows.system"));
        Assert.Empty(RetentionSettings.Suggested.Validate());
    }

    [Fact]
    public void Sql_expression_matches_the_in_memory_decision()
    {
        var p = Policy(120, new(null, "unifi.*", 30), new("globex", "unifi.firewall", 7), new(null, "*", 90));
        var parameters = new Dictionary<string, string>();
        var sql = p.ToSql(parameters);
        // Same order as DaysFor: tenant rule first, then prefix, then *, then the default.
        Assert.Equal("multiIf(tenant_id = {r0:String} AND event_dataset = {r1:String}, 7, startsWith(event_dataset, {r2:String}), 30, 1, 90, 120)", sql);
        Assert.Equal(new Dictionary<string, string> { ["r0"] = "globex", ["r1"] = "unifi.firewall", ["r2"] = "unifi." }, parameters);
        Assert.Equal("120", Policy(120).ToSql([]));
    }

    [Theory]
    [InlineData(0, "windows.security", 30, false, 30, "default must be between")]
    [InlineData(120, "windows.security", 0, false, 30, "keep between")]
    [InlineData(120, "Windows Security", 30, false, 30, "isn't a dataset name")]
    [InlineData(120, "unifi.*x", 30, false, 30, "isn't a dataset name")]
    [InlineData(120, "windows.security", 30, true, 400, "before they're deleted")]
    [InlineData(120, "windows.security", 365, true, 200, null)] // moves before the 365-day rule expires
    public void Settings_are_validated(int defaultDays, string dataset, int days, bool cold, int coldAfter, string? error)
    {
        var problems = new RetentionSettings(defaultDays, [new(null, dataset, days)], cold, coldAfter).Validate().ToList();
        if (error is null)
        {
            Assert.Empty(problems);
        }
        else
        {
            Assert.Contains(problems, x => x.Contains(error, StringComparison.Ordinal));
        }
        Assert.Contains(new RetentionSettings(120, [new(null, "a", 5), new(null, "a", 6)]).Validate(), x => x.Contains("twice", StringComparison.Ordinal));
    }
}

public sealed class StorageTtlTests
{
    [Fact]
    public void Ttl_clause_is_read_from_the_create_statement()
    {
        const string create = "CREATE TABLE dgsiem.events (`x` UInt8) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (tenant_id, event_dataset, timestamp) " +
            "TTL toDateTime(timestamp) + toIntervalDay(30) TO VOLUME 'cold', toDateTime(timestamp) + toIntervalDay(retention_days) SETTINGS index_granularity = 8192";
        Assert.Equal("TTL toDateTime(timestamp) + toIntervalDay(30) TO VOLUME 'cold', toDateTime(timestamp) + toIntervalDay(retention_days)",
            DreaminGeek.Siem.Storage.ClickHouse.ClickHouseStorage.TtlClause(create));
        Assert.Equal(string.Empty, DreaminGeek.Siem.Storage.ClickHouse.ClickHouseStorage.TtlClause("CREATE TABLE t (x UInt8) ENGINE = MergeTree ORDER BY x"));
    }

    [Fact]
    public void Ttl_as_clickhouse_shows_it_counts_as_unchanged()
    {
        // Exactly what ClickHouse 25.8 returned in create_table_query after each ALTER.
        const string tiered = "TTL toDateTime(timestamp) + toIntervalDay(30) TO VOLUME 'cold', toDateTime(timestamp) + toIntervalDay(retention_days)";
        const string plain = "TTL toDateTime(timestamp) + toIntervalDay(retention_days)";
        Assert.True(DreaminGeek.Siem.Storage.ClickHouse.ClickHouseStorage.SameTtl(tiered,
            "toDateTime(timestamp) + toIntervalDay(30) TO VOLUME 'cold', toDateTime(timestamp) + toIntervalDay(retention_days) DELETE"));
        Assert.True(DreaminGeek.Siem.Storage.ClickHouse.ClickHouseStorage.SameTtl(plain, "toDateTime(timestamp) + toIntervalDay(retention_days) DELETE"));
        Assert.False(DreaminGeek.Siem.Storage.ClickHouse.ClickHouseStorage.SameTtl(tiered,
            "toDateTime(timestamp) + toIntervalDay(60) TO VOLUME 'cold', toDateTime(timestamp) + toIntervalDay(retention_days) DELETE"));
        Assert.False(DreaminGeek.Siem.Storage.ClickHouse.ClickHouseStorage.SameTtl(plain,
            "toDateTime(timestamp) + toIntervalDay(30) TO VOLUME 'cold', toDateTime(timestamp) + toIntervalDay(retention_days) DELETE"));
    }
}
