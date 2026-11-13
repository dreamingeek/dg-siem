using System.Text.Json;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Web.Admin;
using DreaminGeek.Siem.Web.Security;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Alerts;

/// <summary>Editable alert rule, bound by the editor page.</summary>
public sealed class AlertRuleForm
{
    public Guid? Id { get; set; }
    public AlertRuleKind Kind { get; set; } = AlertRuleKind.Search;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Query { get; set; } = string.Empty;
    /// <summary>Tenant slug; empty = every tenant.</summary>
    public string Tenant { get; set; } = string.Empty;
    public string TimeRange { get; set; } = "15m";
    public string Schedule { get; set; } = "*/5 * * * *";
    public AlertCondition Condition { get; set; }
    public long Threshold { get; set; }
    public AlertTrigger Trigger { get; set; }
    public AlertSeverity Severity { get; set; } = AlertSeverity.Medium;
    public string? SuppressBy { get; set; }
    public int SuppressMinutes { get; set; } = 60;
    public string? EmailTo { get; set; }
    public bool CreateTicket { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed record AlertRuleSummary(
    Guid Id, string Name, string? Description, string? Tenant, AlertSeverity Severity, string Schedule, bool Enabled,
    bool Emails, bool Tickets, DateTimeOffset? LastRunAt, DateTimeOffset? LastFiredAt, string? LastError, DateTimeOffset? NextRun, int Fired7d);

public sealed record AlertFiringView(
    Guid Id, Guid RuleId, string RuleName, string RuleQuery, string Tenant, DateTimeOffset FiredAt, DateTimeOffset WindowStart, DateTimeOffset WindowEnd,
    AlertSeverity Severity, string Title, long ResultCount, int SuppressedCount, DateTimeOffset? LastSuppressedAt, AlertFiringStatus Status,
    string? TicketNumber, IReadOnlyList<AlertActionResult> Actions, IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<string>> Rows);

public sealed record TenantPsaMapping(Guid TenantId, string Slug, string Name, string? ClientId, string? ClientName, string? BoardId, string? BoardName);

/// <summary>Alert rules, history and notification settings for the UI. Global admins only.</summary>
public sealed class AlertAdminService(
    IDbContextFactory<SiemDbContext> dbFactory,
    AlertRunner runner,
    AlertEvaluator evaluator,
    SettingsStore settings,
    IEmailSender email,
    AlgaPsaClient psa,
    TenantAccess access)
{
    public static readonly (string Cron, string Label)[] SchedulePresets =
    [
        ("* * * * *", "Every minute"),
        ("*/5 * * * *", "Every 5 minutes"),
        ("*/15 * * * *", "Every 15 minutes"),
        ("0 * * * *", "Every hour"),
        ("0 */4 * * *", "Every 4 hours"),
        ("0 8 * * *", "Daily at 8:00"),
        ("0 8 * * 1", "Mondays at 8:00"),
    ];

    public static string DescribeSchedule(string cron) =>
        SchedulePresets.FirstOrDefault(p => p.Cron == cron.Trim()).Label ?? cron;

    // ------------------------------------------------------------------ rules

    public async Task<IReadOnlyList<AlertRuleSummary>> ListRulesAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        var zone = (await settings.GetGeneralAsync(ct)).Zone;
        var since = DateTimeOffset.UtcNow.AddDays(-7);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var rules = await db.AlertRules.AsNoTracking().Include(r => r.Tenant).OrderBy(r => r.Name).ToListAsync(ct);
        var counts = await db.AlertFirings.Where(f => f.FiredAt > since)
            .GroupBy(f => f.AlertRuleId).Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        return rules.Select(r => new AlertRuleSummary(
            r.Id, r.Name, r.Description, r.Tenant?.Slug, r.Severity, DescribeSchedule(r.Schedule), r.Enabled,
            AlertDispatcher.Recipients(r.EmailTo).Count > 0, r.CreateTicket, r.LastRunAt, r.LastFiredAt, r.LastError,
            r.Enabled ? AlertRunner.NextRun(r, zone) : null, counts.GetValueOrDefault(r.Id))).ToList();
    }

    public async Task<AlertRuleForm?> GetRuleAsync(UserAccess caller, Guid id, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var r = await db.AlertRules.AsNoTracking().Include(x => x.Tenant).FirstOrDefaultAsync(x => x.Id == id, ct);
        return r is null ? null : new AlertRuleForm
        {
            Id = r.Id,
            Kind = r.Kind,
            Name = r.Name,
            Description = r.Description,
            Query = r.Query,
            Tenant = r.Tenant?.Slug ?? string.Empty,
            TimeRange = r.TimeRange.TrimStart('-'),
            Schedule = r.Schedule,
            Condition = r.Condition,
            Threshold = r.Threshold,
            Trigger = r.Trigger,
            Severity = r.Severity,
            SuppressBy = r.SuppressBy,
            SuppressMinutes = (int)r.SuppressFor.TotalMinutes,
            EmailTo = r.EmailTo,
            CreateTicket = r.CreateTicket,
            Enabled = r.Enabled,
        };
    }

    public async Task<Guid> SaveRuleAsync(UserAccess caller, AlertRuleForm form, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        ArgumentNullException.ThrowIfNull(form);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var tenantId = await ValidateAsync(db, form, ct);

        AlertRule rule;
        if (form.Id is { } id)
        {
            rule = await db.AlertRules.FirstOrDefaultAsync(r => r.Id == id, ct) ?? throw new AdminException("That alert no longer exists.");
            var scheduleChanged = rule.Schedule != form.Schedule.Trim();
            Apply(rule, form, tenantId);
            if (scheduleChanged)
            {
                // Start the new schedule from now rather than "catching up".
                rule.LastRunAt = DateTimeOffset.UtcNow;
            }
        }
        else
        {
            rule = new AlertRule { Id = Guid.NewGuid(), Name = form.Name, Query = form.Query };
            Apply(rule, form, tenantId);
            db.AlertRules.Add(rule);
        }
        rule.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return rule.Id;
    }

    public async Task SetEnabledAsync(UserAccess caller, Guid id, bool enabled, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var rule = await db.AlertRules.FirstOrDefaultAsync(r => r.Id == id, ct) ?? throw new AdminException("That alert no longer exists.");
        rule.Enabled = enabled;
        if (enabled)
        {
            // Resume from now: a rule turned off for a week shouldn't run immediately for the gap.
            rule.LastRunAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteRuleAsync(UserAccess caller, Guid id, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.AlertRules.Where(r => r.Id == id).ExecuteDeleteAsync(ct);
    }

    /// <summary>Runs a saved rule now and sends what fires (suppression still applies).</summary>
    public async Task<int> RunNowAsync(UserAccess caller, Guid id, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        return await runner.RunAsync(id, ct);
    }

    /// <summary>Evaluates the form without saving or sending anything.</summary>
    public async Task<IReadOnlyList<AlertPreview>> PreviewAsync(UserAccess caller, AlertRuleForm form, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        ArgumentNullException.ThrowIfNull(form);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var tenantId = await ValidateAsync(db, form, ct, forPreview: true);
        var rule = new AlertRule { Id = form.Id ?? Guid.Empty, Kind = form.Kind, Name = form.Name, Query = form.Query };
        Apply(rule, form, tenantId);
        try
        {
            return await runner.PreviewAsync(rule, ct);
        }
        catch (AlertRuleException ex)
        {
            throw new AdminException(ex.Message);
        }
    }

    private async Task<Guid?> ValidateAsync(SiemDbContext db, AlertRuleForm form, CancellationToken ct, bool forPreview = false)
    {
        form.Name = (form.Name ?? string.Empty).Trim();
        form.Query = (form.Query ?? string.Empty).Trim();
        if (!forPreview)
        {
            if (form.Name.Length is 0 or > 200)
            {
                throw new AdminException("Give the alert a name (up to 200 characters).");
            }
            if (await db.AlertRules.AnyAsync(r => r.Name == form.Name && r.Id != form.Id, ct))
            {
                throw new AdminException($"There's already an alert named \"{form.Name}\".");
            }
        }
        if (form.Kind != AlertRuleKind.Search)
        {
            // Health checks have no search: they look at agents and sources as they are when the rule runs.
            form.Query = string.Empty;
            form.TimeRange = "1h";
            form.Condition = AlertCondition.AnyResults;
            form.Threshold = 0;
            form.Trigger = AlertTrigger.Once;
            form.SuppressBy = null;
        }
        else if (form.Query.Length == 0)
        {
            throw new AdminException("Enter the search the alert runs.");
        }
        try
        {
            if (form.Kind == AlertRuleKind.Search)
            {
                evaluator.Validate(form.Query);
            }
            AlertEvaluator.ParseLookback(form.TimeRange);
            AlertRunner.ParseSchedule(form.Schedule);
        }
        catch (AlertRuleException ex)
        {
            throw new AdminException(ex.Message);
        }
        if (form.Threshold < 0)
        {
            throw new AdminException("The threshold can't be negative.");
        }
        if (form.SuppressMinutes < 0)
        {
            throw new AdminException("The quiet period can't be negative.");
        }
        if (AlertDispatcher.InvalidRecipient(form.EmailTo) is { } bad)
        {
            throw new AdminException($"\"{bad}\" isn't an email address.");
        }

        if (string.IsNullOrEmpty(form.Tenant))
        {
            return null;
        }
        return await db.Tenants.Where(t => t.Slug == form.Tenant).Select(t => (Guid?)t.Id).FirstOrDefaultAsync(ct)
            ?? throw new AdminException($"Tenant \"{form.Tenant}\" doesn't exist.");
    }

    private static void Apply(AlertRule rule, AlertRuleForm form, Guid? tenantId)
    {
        rule.Kind = form.Kind;
        rule.Name = form.Name;
        rule.Description = string.IsNullOrWhiteSpace(form.Description) ? null : form.Description.Trim();
        rule.Query = form.Query;
        rule.TenantId = tenantId;
        rule.TimeRange = "-" + form.TimeRange.Trim().TrimStart('-');
        rule.Schedule = form.Schedule.Trim();
        rule.Condition = form.Condition;
        rule.Threshold = form.Threshold;
        rule.Trigger = form.Trigger;
        rule.Severity = form.Severity;
        rule.SuppressBy = string.IsNullOrWhiteSpace(form.SuppressBy) ? null : form.SuppressBy.Trim();
        rule.SuppressFor = TimeSpan.FromMinutes(form.SuppressMinutes);
        rule.EmailTo = AlertDispatcher.Recipients(form.EmailTo) is { Count: > 0 } to ? string.Join(", ", to) : null;
        rule.CreateTicket = form.CreateTicket;
        rule.Enabled = form.Enabled;
    }

    // ------------------------------------------------------------------ history

    public async Task<IReadOnlyList<AlertFiringView>> HistoryAsync(UserAccess caller, Guid? ruleId, Guid? firingId, int limit, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var query = db.AlertFirings.AsNoTracking().Include(f => f.AlertRule).AsQueryable();
        if (firingId is { } fid)
        {
            query = query.Where(f => f.Id == fid);
        }
        else if (ruleId is { } rid)
        {
            query = query.Where(f => f.AlertRuleId == rid);
        }
        var firings = await query.OrderByDescending(f => f.FiredAt).Take(Math.Clamp(limit, 1, 500)).ToListAsync(ct);
        return firings.Select(View).ToList();
    }

    private static AlertFiringView View(AlertFiring f)
    {
        IReadOnlyList<AlertActionResult> actions = [];
        IReadOnlyList<string> columns = [];
        IReadOnlyList<IReadOnlyList<string>> rows = [];
        try
        {
            actions = JsonSerializer.Deserialize<List<AlertActionResult>>(f.ActionResultsJson, Json) ?? [];
            var sample = JsonSerializer.Deserialize<Sample>(f.SampleJson, Json);
            columns = sample?.Columns ?? [];
            rows = sample?.Rows ?? [];
        }
        catch (JsonException)
        {
            // Older or hand-edited rows: show what we can.
        }
        return new AlertFiringView(
            f.Id, f.AlertRuleId, f.AlertRule.Name, f.AlertRule.Query, f.TenantSlug, f.FiredAt, f.WindowStart, f.WindowEnd, f.Severity, f.Title,
            f.ResultCount, f.SuppressedCount, f.LastSuppressedAt, f.Status, f.TicketNumber, actions, columns, rows);
    }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private sealed record Sample(List<string>? Columns, List<List<string>>? Rows);

    // ------------------------------------------------------------------ settings

    public async Task<(GeneralSettings General, SmtpSettings Smtp, PsaSettings Psa)> GetSettingsAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        return (await settings.GetGeneralAsync(ct), await settings.GetSmtpAsync(ct), await settings.GetPsaAsync(ct));
    }

    public async Task SaveGeneralAsync(UserAccess caller, GeneralSettings general, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        ArgumentNullException.ThrowIfNull(general);
        if (!string.IsNullOrWhiteSpace(general.PublicUrl)
            && (!Uri.TryCreate(general.PublicUrl.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http")))
        {
            throw new AdminException("The link address must start with https:// (or http://).");
        }
        if (!TimeZoneInfo.TryFindSystemTimeZoneById(general.TimeZone, out _))
        {
            throw new AdminException($"Unknown time zone \"{general.TimeZone}\".");
        }
        await settings.SaveGeneralAsync(general, ct);
    }

    /// <param name="smtp">A null password keeps the saved one.</param>
    public async Task SaveSmtpAsync(UserAccess caller, SmtpSettings smtp, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        ArgumentNullException.ThrowIfNull(smtp);
        if (smtp.Host.Trim().Length > 0)
        {
            if (smtp.Port is < 1 or > 65535)
            {
                throw new AdminException("The SMTP port must be between 1 and 65535.");
            }
            if (AlertDispatcher.InvalidRecipient(smtp.FromAddress) is not null || smtp.FromAddress.Trim().Length == 0)
            {
                throw new AdminException("Enter a valid From address.");
            }
        }
        await settings.SaveSmtpAsync(smtp, ct);
    }

    public async Task SendTestEmailAsync(UserAccess caller, string to, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        if (AlertDispatcher.Recipients(to).Count == 0 || AlertDispatcher.InvalidRecipient(to) is not null)
        {
            throw new AdminException("Enter the address to send the test to.");
        }
        try
        {
            await email.SendAsync(await settings.GetSmtpAsync(ct), AlertDispatcher.Recipients(to), "[DG SIEM] Test email",
                "<p style=\"font-family:Segoe UI,Helvetica,Arial,sans-serif\">Email from DG SIEM works. Alerts will arrive like this.</p>",
                "Email from DG SIEM works. Alerts will arrive like this.", ct);
        }
        catch (EmailException ex)
        {
            throw new AdminException(ex.Message);
        }
    }

    /// <param name="psaSettings">A null API key keeps the saved one.</param>
    public async Task SavePsaAsync(UserAccess caller, PsaSettings psaSettings, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        ArgumentNullException.ThrowIfNull(psaSettings);
        if (psaSettings.BaseUrl.Trim().Length > 0
            && (!Uri.TryCreate(psaSettings.BaseUrl.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http")))
        {
            throw new AdminException("The AlgaPSA address must start with https://.");
        }
        await settings.SavePsaAsync(psaSettings, ct);
    }

    /// <summary>Boards, clients and priorities from AlgaPSA (also proves the URL and key work).</summary>
    public async Task<(IReadOnlyList<PsaRef> Boards, IReadOnlyList<PsaRef> Clients, IReadOnlyList<PsaRef> Priorities)> LoadPsaListsAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        var config = await settings.GetPsaAsync(ct);
        try
        {
            return (await psa.BoardsAsync(config, ct), await psa.ClientsAsync(config, ct), await psa.PrioritiesAsync(config, ct));
        }
        catch (PsaException ex)
        {
            throw new AdminException(ex.Message);
        }
    }

    public async Task<IReadOnlyList<TenantPsaMapping>> TenantMappingsAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Tenants.AsNoTracking().OrderBy(t => t.Slug)
            .Select(t => new TenantPsaMapping(t.Id, t.Slug, t.Name, t.PsaClientId, t.PsaClientName, t.PsaBoardId, t.PsaBoardName))
            .ToListAsync(ct);
    }

    public async Task SaveTenantMappingsAsync(UserAccess caller, IEnumerable<TenantPsaMapping> mappings, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can manage alerts.", ct);
        ArgumentNullException.ThrowIfNull(mappings);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var tenants = await db.Tenants.ToDictionaryAsync(t => t.Id, ct);
        foreach (var m in mappings)
        {
            if (tenants.TryGetValue(m.TenantId, out var t))
            {
                t.PsaClientId = string.IsNullOrEmpty(m.ClientId) ? null : m.ClientId;
                t.PsaClientName = t.PsaClientId is null ? null : m.ClientName;
                t.PsaBoardId = string.IsNullOrEmpty(m.BoardId) ? null : m.BoardId;
                t.PsaBoardName = t.PsaBoardId is null ? null : m.BoardName;
            }
        }
        await db.SaveChangesAsync(ct);
    }

}
