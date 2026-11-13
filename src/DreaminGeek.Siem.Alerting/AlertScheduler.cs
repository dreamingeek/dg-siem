using System.Collections.Concurrent;
using Cronos;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DreaminGeek.Siem.Alerting;

/// <summary>What a rule would do right now, per tenant (the editor's Test button). Nothing is sent.</summary>
public sealed record AlertPreview(string Tenant, AlertEvaluation? Evaluation, string? Error);

/// <summary>Runs alert rules: on schedule (via <see cref="AlertScheduler"/>), on demand, or as a dry run.</summary>
public sealed partial class AlertRunner(
    IDbContextFactory<SiemDbContext> dbFactory,
    AlertEvaluator evaluator,
    IHealthAlertSource health,
    AlertDispatcher dispatcher,
    SettingsStore settings,
    TimeProvider time,
    ILogger<AlertRunner> logger)
{
    /// <summary>Firings older than this are deleted.</summary>
    public static readonly TimeSpan HistoryRetention = TimeSpan.FromDays(180);

    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _ruleLocks = new();
    private DateTimeOffset _lastCleanup = DateTimeOffset.MinValue;

    public static CronExpression ParseSchedule(string schedule)
    {
        try
        {
            return CronExpression.Parse((schedule ?? string.Empty).Trim());
        }
        catch (CronFormatException ex)
        {
            throw new AlertRuleException($"\"{schedule}\" isn't a valid schedule: {ex.Message}");
        }
    }

    /// <summary>When the rule runs next, in the schedule's time zone.</summary>
    public static DateTimeOffset? NextRun(AlertRule rule, TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(rule);
        try
        {
            return ParseSchedule(rule.Schedule).GetNextOccurrence(rule.LastRunAt ?? rule.CreatedAt, zone);
        }
        catch (AlertRuleException)
        {
            return null;
        }
    }

    /// <summary>Runs every enabled rule that is due. Missed runs (server down) collapse into one.</summary>
    public async Task RunDueAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var zone = (await settings.GetGeneralAsync(ct)).Zone;
        List<Guid> due;
        await using (var db = await dbFactory.CreateDbContextAsync(ct))
        {
            var rules = await db.AlertRules.AsNoTracking().Where(r => r.Enabled).ToListAsync(ct);
            due = rules.Where(r => NextRun(r, zone) is { } next && next <= now).Select(r => r.Id).ToList();
        }

        foreach (var id in due)
        {
            ct.ThrowIfCancellationRequested();
            await RunAsync(id, ct);
        }

        if (now - _lastCleanup > TimeSpan.FromHours(1))
        {
            _lastCleanup = now;
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var cutoff = now - HistoryRetention;
            await db.AlertFirings.Where(f => f.FiredAt < cutoff).ExecuteDeleteAsync(ct);
        }
    }

    /// <summary>Runs one rule now (scheduled or "Run now") and sends whatever fires.</summary>
    /// <returns>Alerts sent (suppressed repeats not counted).</returns>
    public async Task<int> RunAsync(Guid ruleId, CancellationToken ct)
    {
        var gate = _ruleLocks.GetOrAdd(ruleId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var rule = await db.AlertRules.Include(r => r.Tenant).FirstOrDefaultAsync(r => r.Id == ruleId, ct);
            if (rule is null)
            {
                return 0;
            }

            var now = time.GetUtcNow();
            var errors = new List<string>();
            var fired = 0;
            try
            {
                var (from, to) = AlertEvaluator.Window(rule.TimeRange, now);
                foreach (var tenant in await TenantsAsync(db, rule, ct))
                {
                    try
                    {
                        var evaluation = await EvaluateAsync(rule, tenant.Slug, from, to, now, ct);
                        foreach (var group in evaluation.Groups)
                        {
                            if (await dispatcher.DispatchAsync(rule, tenant, group, evaluation, from, to, ct) is not null)
                            {
                                fired++;
                            }
                        }
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException and not AlertRuleException)
                    {
                        LogTenantFailed(logger, ex, rule.Name, tenant.Slug);
                        errors.Add($"{tenant.Slug}: {FirstLine(ex.Message)}");
                    }
                }
            }
            catch (AlertRuleException ex)
            {
                errors.Add(ex.Message);
            }

            rule.LastRunAt = now;
            rule.LastError = errors.Count == 0 ? null : string.Join("; ", errors);
            if (fired > 0)
            {
                rule.LastFiredAt = now;
            }
            await db.SaveChangesAsync(ct);
            return fired;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Evaluates a (possibly unsaved) rule for each of its tenants without sending anything.</summary>
    public async Task<IReadOnlyList<AlertPreview>> PreviewAsync(AlertRule rule, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var now = time.GetUtcNow();
        var (from, to) = AlertEvaluator.Window(rule.TimeRange, now);
        if (rule.Kind == AlertRuleKind.Search)
        {
            evaluator.Validate(rule.Query);
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var previews = new List<AlertPreview>();
        foreach (var tenant in await TenantsAsync(db, rule, ct))
        {
            try
            {
                previews.Add(new AlertPreview(tenant.Slug, await EvaluateAsync(rule, tenant.Slug, from, to, now, ct), null));
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not AlertRuleException)
            {
                previews.Add(new AlertPreview(tenant.Slug, null, FirstLine(ex.Message)));
            }
        }
        return previews;
    }

    private Task<AlertEvaluation> EvaluateAsync(AlertRule rule, string tenant, DateTimeOffset from, DateTimeOffset to, DateTimeOffset now, CancellationToken ct) =>
        rule.Kind == AlertRuleKind.Search
            ? evaluator.EvaluateAsync(rule, tenant, from, to, ct)
            : health.EvaluateAsync(rule, tenant, now, ct);

    private static async Task<List<Tenant>> TenantsAsync(SiemDbContext db, AlertRule rule, CancellationToken ct) =>
        rule.TenantId is { } id
            ? await db.Tenants.AsNoTracking().Where(t => t.Id == id).ToListAsync(ct)
            : await db.Tenants.AsNoTracking().OrderBy(t => t.Slug).ToListAsync(ct);

    private static string FirstLine(string message) => message.Split('\n')[0].Trim();

    [LoggerMessage(Level = LogLevel.Warning, Message = "Alert {Rule} failed for tenant {Tenant}")]
    private static partial void LogTenantFailed(ILogger logger, Exception ex, string rule, string tenant);
}

/// <summary>Checks for due alert rules every 15 seconds.</summary>
public sealed partial class AlertScheduler(AlertRunner runner, ILogger<AlertScheduler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Let startup (migrations, row-policy setup) settle first.
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        do
        {
            try
            {
                await runner.RunDueAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogLoopFailed(logger, ex);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Alert scheduler pass failed")]
    private static partial void LogLoopFailed(ILogger logger, Exception ex);
}
