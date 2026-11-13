using System.Text.Json;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace DreaminGeek.Siem.Alerting;

/// <summary>Outcome of one action on one firing (stored as JSON on the firing).</summary>
public sealed record AlertActionResult(string Action, bool Ok, string Detail);

/// <summary>
/// Turns a matched alert into notifications: applies suppression, sends the email, opens (or comments on)
/// the AlgaPSA ticket, and records the <see cref="AlertFiring"/>.
/// </summary>
public sealed partial class AlertDispatcher(
    IDbContextFactory<SiemDbContext> dbFactory,
    SettingsStore settings,
    IEmailSender email,
    AlgaPsaClient psa,
    TimeProvider time,
    ILogger<AlertDispatcher> logger)
{
    /// <summary>A repeat alert comments on the earlier ticket while it's still open, if it was opened this recently.</summary>
    public static readonly TimeSpan TicketReuseWindow = TimeSpan.FromDays(30);

    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string SuppressionKey(string tenant, AlertGroup group) => $"{tenant}|{group?.Key}";

    /// <returns>The firing, or null when suppressed.</returns>
    public async Task<AlertFiring?> DispatchAsync(
        AlertRule rule, Tenant tenant, AlertGroup group, AlertEvaluation evaluation,
        DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(evaluation);

        var now = time.GetUtcNow();
        var key = SuppressionKey(tenant.Slug, group);

        await using (var db = await dbFactory.CreateDbContextAsync(ct))
        {
            if (rule.SuppressFor > TimeSpan.Zero)
            {
                var since = now - rule.SuppressFor;
                var recent = await db.AlertFirings
                    .Where(f => f.AlertRuleId == rule.Id && f.SuppressionKey == key && f.FiredAt > since)
                    .OrderByDescending(f => f.FiredAt)
                    .FirstOrDefaultAsync(ct);
                if (recent is not null)
                {
                    recent.SuppressedCount++;
                    recent.LastSuppressedAt = now;
                    await db.SaveChangesAsync(ct);
                    LogSuppressed(logger, rule.Name, key);
                    return null;
                }
            }
        }

        var general = await settings.GetGeneralAsync(ct);
        var firing = new AlertFiring
        {
            Id = Guid.NewGuid(),
            AlertRuleId = rule.Id,
            TenantSlug = tenant.Slug,
            FiredAt = now,
            WindowStart = from,
            WindowEnd = to,
            Severity = rule.Severity,
            Title = string.Empty,
            ResultCount = evaluation.Count,
            SuppressionKey = key,
            SampleJson = JsonSerializer.Serialize(new
            {
                columns = evaluation.Columns,
                rows = group.Rows.Take(AlertEvaluator.SampleRows).Select(r => r.Select(AlertEvaluator.Text)),
            }, Json),
        };
        var message = AlertMessage.Build(rule, tenant, group, evaluation, from, to, firing.Id, general);
        firing.Title = message.Title.Length > 500 ? message.Title[..500] : message.Title;

        var results = new List<AlertActionResult>();
        var recipients = Recipients(rule.EmailTo);
        if (recipients.Count > 0)
        {
            results.Add(await SendEmailAsync(recipients, message, ct));
        }
        if (rule.CreateTicket)
        {
            results.Add(await TicketAsync(rule, tenant, firing, message, ct));
        }

        firing.ActionResultsJson = JsonSerializer.Serialize(results, Json);
        firing.Status = results.Count == 0 ? AlertFiringStatus.Recorded
            : results.TrueForAll(r => r.Ok) ? AlertFiringStatus.Sent
            : results.Exists(r => r.Ok) ? AlertFiringStatus.Partial
            : AlertFiringStatus.Failed;

        await using (var db = await dbFactory.CreateDbContextAsync(ct))
        {
            db.AlertFirings.Add(firing);
            await db.SaveChangesAsync(ct);
        }
        LogFired(logger, rule.Name, tenant.Slug, group.Label, firing.Status);
        return firing;
    }

    public static IReadOnlyList<string> Recipients(string? emailTo) =>
        (emailTo ?? string.Empty)
            .Split([',', ';', '\n', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>Null when every address is valid, otherwise the first bad one.</summary>
    public static string? InvalidRecipient(string? emailTo) =>
        Recipients(emailTo).FirstOrDefault(a => !MailboxAddress.TryParse(a, out var parsed) || !parsed.Address.Contains('@', StringComparison.Ordinal));

    private async Task<AlertActionResult> SendEmailAsync(IReadOnlyList<string> recipients, AlertMessage message, CancellationToken ct)
    {
        try
        {
            var smtp = await settings.GetSmtpAsync(ct);
            await email.SendAsync(smtp, recipients, message.Subject, message.Html, message.Text, ct);
            return new AlertActionResult("email", true, $"Sent to {string.Join(", ", recipients)}");
        }
        catch (EmailException ex)
        {
            LogActionFailed(logger, ex, "email");
            return new AlertActionResult("email", false, ex.Message);
        }
    }

    private async Task<AlertActionResult> TicketAsync(AlertRule rule, Tenant tenant, AlertFiring firing, AlertMessage message, CancellationToken ct)
    {
        try
        {
            var config = await settings.GetPsaAsync(ct);
            if (string.IsNullOrEmpty(tenant.PsaClientId))
            {
                throw new PsaException($"Tenant {tenant.Slug} isn't linked to an AlgaPSA client. Set it under Administration → Notifications.");
            }
            var board = tenant.PsaBoardId ?? config.DefaultBoard?.Id
                ?? throw new PsaException("No AlgaPSA board is chosen. Set a default board under Administration → Notifications.");
            if (!config.Priorities.TryGetValue(rule.Severity, out var priority))
            {
                throw new PsaException($"No AlgaPSA priority is chosen for {rule.Severity} alerts. Set it under Administration → Notifications.");
            }

            // A repeat of an alert whose ticket is still open becomes a note on that ticket.
            var previous = await PreviousTicketAsync(rule.Id, firing.SuppressionKey, firing.FiredAt - TicketReuseWindow, ct);
            if (previous is not null && await psa.IsOpenAsync(config, previous.Value.Id, ct))
            {
                var lines = new List<string> { $"This alert fired again at {firing.FiredAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC.", string.Empty };
                lines.AddRange(message.TicketLines);
                await psa.AddCommentAsync(config, previous.Value.Id, lines, message.SearchLink, ct);
                firing.TicketId = previous.Value.Id;
                firing.TicketNumber = previous.Value.Number;
                return new AlertActionResult("ticket", true, $"Added a note to open ticket {previous.Value.Number}");
            }

            var ticket = await psa.CreateTicketAsync(config, new NewPsaTicket(
                $"[DG SIEM] {message.Title}", tenant.PsaClientId, board, priority.Id, message.TicketLines,
                message.SearchLink, firing.Id.ToString()), ct);
            firing.TicketId = ticket.Id;
            firing.TicketNumber = ticket.Number;
            return new AlertActionResult("ticket", true, $"Opened ticket {ticket.Number}");
        }
        catch (PsaException ex)
        {
            LogActionFailed(logger, ex, "ticket");
            return new AlertActionResult("ticket", false, ex.Message);
        }
    }

    private async Task<(string Id, string Number)?> PreviousTicketAsync(Guid ruleId, string key, DateTimeOffset since, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var previous = await db.AlertFirings.AsNoTracking()
            .Where(f => f.AlertRuleId == ruleId && f.SuppressionKey == key && f.TicketId != null && f.FiredAt > since)
            .OrderByDescending(f => f.FiredAt)
            .Select(f => new { f.TicketId, f.TicketNumber })
            .FirstOrDefaultAsync(ct);
        return previous is null ? null : (previous.TicketId!, previous.TicketNumber ?? previous.TicketId!);
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Alert {Rule} suppressed for {Key}")]
    private static partial void LogSuppressed(ILogger logger, string rule, string key);

    [LoggerMessage(Level = LogLevel.Information, Message = "Alert {Rule} fired for {Tenant} {Group}: {Status}")]
    private static partial void LogFired(ILogger logger, string rule, string tenant, string group, AlertFiringStatus status);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Alert {Action} action failed")]
    private static partial void LogActionFailed(ILogger logger, Exception ex, string action);
}
