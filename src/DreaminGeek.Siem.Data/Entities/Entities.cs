using Microsoft.AspNetCore.Identity;

namespace DreaminGeek.Siem.Data.Entities;

/// <summary>A local DG SIEM login. OIDC (Authentik etc.) is an optional add-on later.</summary>
public sealed class SiemUser : IdentityUser<Guid>
{
    public string DisplayName { get; set; } = string.Empty;
    public bool IsGlobalAdmin { get; set; }
    public ICollection<TenantMembership> Memberships { get; } = [];
}

/// <summary>A client (or your own org). Slug matches your naming prefix: <c>dg</c>, <c>acme</c>, <c>globex</c>.</summary>
public sealed class Tenant
{
    public Guid Id { get; set; }
    public required string Slug { get; set; }
    public required string Name { get; set; }
    public int RetentionDays { get; set; } = 120;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>AlgaPSA client that alert tickets for this tenant are filed under.</summary>
    public string? PsaClientId { get; set; }
    public string? PsaClientName { get; set; }
    /// <summary>AlgaPSA board for this tenant's tickets; null = the default board.</summary>
    public string? PsaBoardId { get; set; }
    public string? PsaBoardName { get; set; }
    public ICollection<CollectorAgent> Agents { get; } = [];
}

public enum TenantRole
{
    Viewer = 0,
    Admin = 1,
}

public sealed class TenantMembership
{
    public Guid UserId { get; set; }
    public SiemUser User { get; set; } = null!;
    public Guid TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;
    public TenantRole Role { get; set; }
}

/// <summary>An enrolled <c>dg-siem-agent</c>, e.g. acme-log-col.</summary>
public sealed class CollectorAgent
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;
    public required string Name { get; set; }
    /// <summary>SHA-256 thumbprint of the agent's mTLS client certificate (issued at enrollment).</summary>
    public string? CertificateThumbprint { get; set; }
    /// <summary>JSON agent config (inputs, ports, dataset hints) pulled by the agent.</summary>
    public string ConfigJson { get; set; } = "{}";
    public DateTimeOffset? LastSeenAt { get; set; }
    public string? Version { get; set; }
    /// <summary><c>linux-x64</c>, <c>linux-arm64</c>, <c>win-x64</c>: reported when the agent checks for updates (0.4.0+).</summary>
    public string? Platform { get; set; }
    public DateTimeOffset? CertificateNotAfter { get; set; }
    /// <summary>Set to block the agent immediately; its certificate stops working on the next request.</summary>
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>Single-use, expiring token used to enroll an agent and issue its certificate.</summary>
public sealed class EnrollmentToken
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;
    /// <summary>Only the hash is stored; the plaintext token is shown once.</summary>
    public required string TokenHash { get; set; }
    /// <summary>If set, the token can only enroll an agent with this name.</summary>
    public string? AgentName { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

public sealed class SavedSearch
{
    public Guid Id { get; set; }
    /// <summary>Null = visible to every tenant the viewer can access (global search, e.g. a shared UniFi search).</summary>
    public Guid? TenantId { get; set; }
    public required string Name { get; set; }
    public required string Query { get; set; }
    /// <summary>Relative range, e.g. <c>-24h</c>.</summary>
    public string TimeRange { get; set; } = "-24h";
    public Guid OwnerId { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class Dashboard
{
    public Guid Id { get; set; }
    public Guid? TenantId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    /// <summary>JSON array of panels: title, query, visualization, grid position and size.</summary>
    public string LayoutJson { get; set; } = "[]";
    /// <summary>Default time range, e.g. <c>-24h</c>.</summary>
    public string TimeRange { get; set; } = "-24h";
    /// <summary>Auto-refresh interval; 0 = off.</summary>
    public int RefreshSeconds { get; set; }
    public Guid OwnerId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public enum AlertCondition
{
    AnyResults = 0,
    CountGreaterThan = 1,
    CountLessThan = 2,
}

public enum AlertSeverity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

public enum AlertTrigger
{
    /// <summary>One alert for the whole result.</summary>
    Once = 0,
    /// <summary>One alert per result row (e.g. per source IP from <c>stats count() by src</c>).</summary>
    PerResult = 1,
}

/// <summary>A saved search run on a schedule. Evaluated separately for each tenant it covers.</summary>
/// <summary>What an alert rule checks.</summary>
public enum AlertRuleKind
{
    /// <summary>Runs <see cref="AlertRule.Query"/> (the usual kind).</summary>
    Search = 0,

    /// <summary>Sources (a host sending a dataset) silent for longer than they usually are (Administration &gt; Health).</summary>
    QuietSources = 1,

    /// <summary>Agents that stopped checking in, or whose backlog isn't being delivered.</summary>
    AgentProblems = 2,
}

public sealed class AlertRule
{
    public Guid Id { get; set; }
    public AlertRuleKind Kind { get; set; } = AlertRuleKind.Search;
    /// <summary>Null = every tenant (each evaluated and alerted separately).</summary>
    public Guid? TenantId { get; set; }
    public Tenant? Tenant { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public required string Query { get; set; }
    /// <summary>Lookback window evaluated on each run, e.g. <c>-15m</c>.</summary>
    public string TimeRange { get; set; } = "-15m";
    /// <summary>Cron expression (Cronos, 5 fields) in the configured time zone, e.g. <c>*/5 * * * *</c>.</summary>
    public string Schedule { get; set; } = "*/5 * * * *";
    public AlertCondition Condition { get; set; }
    public long Threshold { get; set; }
    public AlertTrigger Trigger { get; set; }
    public AlertSeverity Severity { get; set; } = AlertSeverity.Medium;
    /// <summary>Comma-separated fields that make a repeat "the same alert" (per-result alerts), e.g. <c>source.ip</c>.</summary>
    public string? SuppressBy { get; set; }
    /// <summary>After firing, the same alert stays quiet this long (zero = never suppress).</summary>
    public TimeSpan SuppressFor { get; set; } = TimeSpan.FromHours(1);
    /// <summary>Comma-separated email recipients; empty = no email.</summary>
    public string? EmailTo { get; set; }
    public bool CreateTicket { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastRunAt { get; set; }
    public DateTimeOffset? LastFiredAt { get; set; }
    /// <summary>Why the last run failed (bad query, ClickHouse down); null when it worked.</summary>
    public string? LastError { get; set; }
}

public enum AlertFiringStatus
{
    /// <summary>Every action worked.</summary>
    Sent = 0,
    /// <summary>Some actions failed.</summary>
    Partial = 1,
    /// <summary>Every action failed.</summary>
    Failed = 2,
    /// <summary>The rule has no actions; recorded in history only.</summary>
    Recorded = 3,
}

/// <summary>One alert sent (or attempted): a rule matched for one tenant and was not suppressed.</summary>
public sealed class AlertFiring
{
    public Guid Id { get; set; }
    public Guid AlertRuleId { get; set; }
    public AlertRule AlertRule { get; set; } = null!;
    public required string TenantSlug { get; set; }
    public DateTimeOffset FiredAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset WindowStart { get; set; }
    public DateTimeOffset WindowEnd { get; set; }
    public AlertSeverity Severity { get; set; }
    public required string Title { get; set; }
    public long ResultCount { get; set; }
    /// <summary>Tenant + group values; repeats with the same key are suppressed.</summary>
    public required string SuppressionKey { get; set; }
    /// <summary>Repeats suppressed since this firing.</summary>
    public int SuppressedCount { get; set; }
    public DateTimeOffset? LastSuppressedAt { get; set; }
    /// <summary>JSON {columns:[...], rows:[[...]]}: the first results, for history and notifications.</summary>
    public string SampleJson { get; set; } = "{}";
    /// <summary>JSON array of {action, ok, detail}.</summary>
    public string ActionResultsJson { get; set; } = "[]";
    public AlertFiringStatus Status { get; set; }
    /// <summary>AlgaPSA ticket created (or commented on) for this firing.</summary>
    public string? TicketId { get; set; }
    public string? TicketNumber { get; set; }
}

/// <summary>Server-wide settings edited in the UI (SMTP, AlgaPSA, ...). Secrets are stored encrypted.</summary>
public sealed class AppSetting
{
    public required string Key { get; set; }
    public required string Value { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>"Never store events like this", e.g. UniFi IPsec keepalives. See DreaminGeek.Siem.Ingest.DropFilter.</summary>
public sealed class DropRuleEntity
{
    public Guid Id { get; set; }
    /// <summary>Null = applies to every tenant.</summary>
    public Guid? TenantId { get; set; }
    public Tenant? Tenant { get; set; }
    public required string Name { get; set; }
    /// <summary>Exact <c>event.dataset</c>, or a prefix ending in <c>*</c>. Null = any dataset.</summary>
    public string? Dataset { get; set; }
    /// <summary>ECS field to test. Null = drop everything in the dataset.</summary>
    public string? Field { get; set; }
    /// <summary>any | equals | contains | startswith | regex</summary>
    public string Match { get; set; } = "any";
    public string? Value { get; set; }
    public bool Enabled { get; set; } = true;
    public long DroppedTotal { get; set; }
    public DateTimeOffset? LastDroppedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
