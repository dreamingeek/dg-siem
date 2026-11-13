using System.Text;

namespace DreaminGeek.Siem.Core;

/// <summary>
/// Keep events of <paramref name="Dataset"/> for <paramref name="Days"/>, for one tenant or (null) all of them.
/// <paramref name="Dataset"/> is an exact name (<c>windows.security</c>), a prefix ending in <c>*</c>
/// (<c>unifi.*</c>), or <c>*</c> for everything.
/// </summary>
public sealed record RetentionRule(string? Tenant, string Dataset, int Days);

/// <param name="DefaultDays">For events no rule matches.</param>
/// <param name="ColdEnabled">Move older events to the S3 cold volume (needs the <c>tiered</c> storage policy).</param>
/// <param name="ColdAfterDays">Age at which events move to cold storage.</param>
public sealed record RetentionSettings(int DefaultDays, IReadOnlyList<RetentionRule> Rules, bool ColdEnabled = false, int ColdAfterDays = 30)
{
    public const int MinDays = 1;
    public const int MaxDays = 3650;

    /// <summary>Security events a year, noisy traffic a month, the rest 120 days.</summary>
    public static RetentionSettings Suggested { get; } = new(120,
    [
        new(null, "windows.security", 365),
        new(null, "windows.defender", 365),
        new(null, "windows.powershell", 365),
        new(null, "authentik.event", 365),
        new(null, "asterisk.security", 365),
        new(null, "freeswitch.security", 365),
        new(null, "crowdsec.decision", 365),
        new(null, "crowdsec.alert", 365),
        new(null, "unifi.firewall", 30),
        new(null, "unifi.vpn", 30),
        new(null, "traefik.access", 30),
        new(null, "asterisk.sip", 30),
        new(null, "freeswitch.log", 30),
        new(null, "crowdsec.lapi", 30),
        new(null, "authentik.http", 30),
        new(null, "authentik.tasks", 30),
    ]);

    /// <summary>Problems with the settings, or none.</summary>
    public IEnumerable<string> Validate()
    {
        if (DefaultDays is < MinDays or > MaxDays)
        {
            yield return $"The default must be between {MinDays} and {MaxDays} days.";
        }
        if (ColdEnabled && (ColdAfterDays < 1 || ColdAfterDays >= DefaultDays && Rules.All(r => ColdAfterDays >= r.Days)))
        {
            yield return "Events must move to cold storage before they're deleted: make \"after\" shorter than the retention.";
        }
        var seen = new HashSet<(string?, string)>();
        foreach (var rule in Rules)
        {
            if (rule.Days is < MinDays or > MaxDays)
            {
                yield return $"{rule.Dataset}: keep between {MinDays} and {MaxDays} days.";
            }
            if (!RetentionPolicy.IsValidPattern(rule.Dataset))
            {
                yield return $"\"{rule.Dataset}\" isn't a dataset name, a prefix like unifi.*, or *.";
            }
            if (rule.Tenant is { } t && !RetentionPolicy.IsValidName(t))
            {
                yield return $"\"{t}\" isn't a tenant.";
            }
            if (!seen.Add((rule.Tenant?.ToLowerInvariant(), rule.Dataset.ToLowerInvariant())))
            {
                yield return $"{rule.Dataset} is listed twice for {rule.Tenant ?? "all tenants"}.";
            }
        }
    }
}

/// <summary>
/// Resolves how long an event is kept. Tenant-specific rules beat all-tenant rules; within each, an exact dataset
/// beats a longer prefix, which beats a shorter one, which beats <c>*</c>. Thread-safe; <see cref="Update"/> swaps
/// the rules atomically.
/// </summary>
public sealed class RetentionPolicy
{
    private sealed record Compiled(int DefaultDays, IReadOnlyList<RetentionRule> Ordered);

    private volatile Compiled _current = Compile(RetentionSettings.Suggested);

    public RetentionSettings Settings { get; private set; } = RetentionSettings.Suggested;

    public void Update(RetentionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Settings = settings;
        _current = Compile(settings);
    }

    public ushort DaysFor(string tenant, string dataset)
    {
        var c = _current;
        foreach (var rule in c.Ordered)
        {
            if ((rule.Tenant is null || string.Equals(rule.Tenant, tenant, StringComparison.OrdinalIgnoreCase)) && Matches(rule.Dataset, dataset))
            {
                return (ushort)rule.Days;
            }
        }
        return (ushort)c.DefaultDays;
    }

    /// <summary>
    /// The same decision as a ClickHouse expression over <c>tenant_id</c> and <c>event_dataset</c>, for re-stamping
    /// stored events. Values are parameters (<c>{r0:String}</c>...), returned in <paramref name="parameters"/>.
    /// </summary>
    public string ToSql(Dictionary<string, string> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var c = _current;
        if (c.Ordered.Count == 0)
        {
            return c.DefaultDays.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        var sql = new StringBuilder("multiIf(");
        foreach (var rule in c.Ordered)
        {
            var conditions = new List<string>();
            if (rule.Tenant is { } tenant)
            {
                conditions.Add($"tenant_id = {Param(parameters, tenant)}");
            }
            if (rule.Dataset != "*")
            {
                conditions.Add(rule.Dataset.EndsWith('*')
                    ? $"startsWith(event_dataset, {Param(parameters, rule.Dataset[..^1])})"
                    : $"event_dataset = {Param(parameters, rule.Dataset)}");
            }
            sql.Append(conditions.Count == 0 ? "1" : string.Join(" AND ", conditions))
               .Append(", ").Append(rule.Days.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(", ");
        }
        return sql.Append(c.DefaultDays.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(')').ToString();
    }

    private static string Param(Dictionary<string, string> parameters, string value)
    {
        var name = $"r{parameters.Count}";
        parameters[name] = value;
        return $"{{{name}:String}}";
    }

    private static bool Matches(string pattern, string dataset) =>
        pattern == "*"
        || (pattern.EndsWith('*') ? dataset.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase)
                                  : string.Equals(pattern, dataset, StringComparison.OrdinalIgnoreCase));

    private static Compiled Compile(RetentionSettings settings) => new(settings.DefaultDays, settings.Rules
        .OrderBy(r => r.Tenant is null ? 1 : 0)
        .ThenBy(r => r.Dataset == "*" ? 2 : r.Dataset.EndsWith('*') ? 1 : 0)
        .ThenByDescending(r => r.Dataset.Length)
        .ToList());

    /// <summary>Lower-case letters, digits, <c>.</c>, <c>_</c>, <c>-</c>; optionally ending in <c>*</c>; or <c>*</c> alone.</summary>
    public static bool IsValidPattern(string pattern) =>
        pattern == "*" || (pattern.Length is > 0 and <= 100 && IsValidName(pattern.EndsWith('*') ? pattern[..^1] : pattern));

    public static bool IsValidName(string name) =>
        name.Length is > 0 and <= 100 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
}
