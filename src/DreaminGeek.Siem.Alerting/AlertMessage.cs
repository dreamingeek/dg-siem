using System.Globalization;
using System.Net;
using System.Text;
using DreaminGeek.Siem.Data.Entities;

namespace DreaminGeek.Siem.Alerting;

/// <summary>The words of one alert, rendered for email (HTML + text) and AlgaPSA (paragraph lines).</summary>
public sealed record AlertMessage(string Title, string Subject, string Html, string Text, IReadOnlyList<string> TicketLines, string? SearchLink, string? HistoryLink)
{
    /// <summary>Rows shown in a ticket (emails show the full sample).</summary>
    public const int TicketRows = 10;

    public static AlertMessage Build(
        AlertRule rule, Tenant tenant, AlertGroup group, AlertEvaluation evaluation,
        DateTimeOffset from, DateTimeOffset to, Guid firingId, GeneralSettings general)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(evaluation);
        ArgumentNullException.ThrowIfNull(general);

        var labelPart = group.Label.Length > 0 ? $" - {group.Label}" : string.Empty;
        var title = $"{rule.Name}{labelPart} ({tenant.Slug})";
        var subject = $"[DG SIEM] {rule.Severity}: {title}";

        var zone = general.Zone;
        var window = $"{Local(from, zone)} to {Local(to, zone)} {ZoneLabel(zone, to)}";
        var unit = evaluation.CountsEvents ? (evaluation.Count == 1 ? "event" : "events") : (evaluation.Count == 1 ? "result" : "results");
        var matched = $"{evaluation.Count.ToString("N0", CultureInfo.InvariantCulture)} {unit}";
        var condition = rule.Condition switch
        {
            AlertCondition.CountGreaterThan => $" (alerting above {rule.Threshold.ToString("N0", CultureInfo.InvariantCulture)})",
            AlertCondition.CountLessThan => $" (alerting below {rule.Threshold.ToString("N0", CultureInfo.InvariantCulture)})",
            _ => string.Empty,
        };

        var health = rule.Kind != AlertRuleKind.Search;
        var searchLink = health
            ? general.Link($"admin/health?tenant={Uri.EscapeDataString(tenant.Slug)}")
            : general.Link(
                $"search?q={Uri.EscapeDataString(rule.Query)}&from={Uri.EscapeDataString(from.UtcDateTime.ToString("O", CultureInfo.InvariantCulture))}" +
                $"&to={Uri.EscapeDataString(to.UtcDateTime.ToString("O", CultureInfo.InvariantCulture))}&tenant={Uri.EscapeDataString(tenant.Slug)}");
        var historyLink = general.Link($"alerts/history?firing={firingId}");

        var facts = new List<(string Label, string Value)>
        {
            ("Tenant", $"{tenant.Name} ({tenant.Slug})"),
            ("Severity", rule.Severity.ToString()),
        };
        if (health)
        {
            facts.Add(("Found", group.Label));
            facts.Add(("Checked", $"{Local(to, zone)} {ZoneLabel(zone, to)}"));
        }
        else
        {
            facts.Add(("Matched", matched + condition));
            facts.Add(("Window", window));
            if (group.Label.Length > 0)
            {
                facts.Add(("For", group.Label));
            }
            facts.Add(("Query", rule.Query));
        }

        var columns = evaluation.Columns;
        var rows = group.Rows;

        // Plain text: email fallback and ticket body.
        var lines = new List<string> { $"{rule.Name} fired for {tenant.Name}." };
        if (!string.IsNullOrWhiteSpace(rule.Description))
        {
            lines.Add(rule.Description.Trim());
        }
        lines.Add(string.Empty);
        lines.AddRange(facts.Select(f => $"{f.Label}: {f.Value}"));
        if (rows.Count > 0 && columns.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add(health ? "Details:" : rows.Count == 1 ? "Result:" : $"First {Math.Min(rows.Count, TicketRows)} results:");
            lines.AddRange(rows.Take(TicketRows).Select(r => RowText(columns, r)));
        }

        var text = new StringBuilder();
        foreach (var line in lines)
        {
            text.AppendLine(line);
        }
        foreach (var row in rows.Skip(TicketRows))
        {
            text.AppendLine(RowText(columns, row));
        }
        if (searchLink is not null)
        {
            text.AppendLine().Append(health ? "Health: " : "Search: ").AppendLine(searchLink);
        }
        if (historyLink is not null)
        {
            text.Append("Alert: ").AppendLine(historyLink);
        }

        return new AlertMessage(title, subject, RenderHtml(rule, tenant, facts, columns, rows, searchLink, historyLink), text.ToString(), lines, searchLink, historyLink);
    }

    private static string RowText(IReadOnlyList<string> columns, object?[] row) =>
        string.Join(", ", columns.Select((c, i) => $"{c}={AlertEvaluator.Text(row[i])}").Where(s => !s.EndsWith('=')));

    private static string Local(DateTimeOffset time, TimeZoneInfo zone) =>
        TimeZoneInfo.ConvertTime(time, zone).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    private static string ZoneLabel(TimeZoneInfo zone, DateTimeOffset at) =>
        zone == TimeZoneInfo.Utc ? "UTC" : $"{zone.Id} (UTC{FormatOffset(zone.GetUtcOffset(at))})";

    private static string FormatOffset(TimeSpan offset) =>
        (offset < TimeSpan.Zero ? "-" : "+") + offset.Duration().ToString(@"hh\:mm", CultureInfo.InvariantCulture);

    private static string SeverityColor(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => "#c0392b",
        AlertSeverity.High => "#d35400",
        AlertSeverity.Medium => "#b7791f",
        _ => "#4a6278",
    };

    /// <summary>Email body: table-based and inline-styled so it survives Outlook.</summary>
    private static string RenderHtml(
        AlertRule rule, Tenant tenant, List<(string Label, string Value)> facts,
        IReadOnlyList<string> columns, IReadOnlyList<object?[]> rows, string? searchLink, string? historyLink)
    {
        static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
        const string Font = "font-family:Segoe UI,Helvetica,Arial,sans-serif;";
        const string Mono = "font-family:Consolas,Menlo,monospace;font-size:12px;";

        var html = new StringBuilder();
        html.Append(CultureInfo.InvariantCulture, $"<div style=\"{Font}color:#1b2430;font-size:14px;max-width:760px\">");
        html.Append(CultureInfo.InvariantCulture,
            $"<div style=\"border-left:4px solid {SeverityColor(rule.Severity)};padding:4px 0 4px 12px;margin-bottom:16px\">" +
            $"<div style=\"font-size:12px;color:#5b6b7d\">{E(rule.Severity.ToString())} alert · {E(tenant.Name)}</div>" +
            $"<div style=\"font-size:18px;font-weight:600\">{E(rule.Name)}</div></div>");
        if (!string.IsNullOrWhiteSpace(rule.Description))
        {
            html.Append(CultureInfo.InvariantCulture, $"<p style=\"margin:0 0 12px\">{E(rule.Description)}</p>");
        }

        html.Append("<table style=\"border-collapse:collapse;margin-bottom:16px\">");
        foreach (var (label, value) in facts)
        {
            var style = label == "Query" ? Mono : string.Empty;
            html.Append(CultureInfo.InvariantCulture,
                $"<tr><td style=\"padding:2px 16px 2px 0;color:#5b6b7d;vertical-align:top\">{E(label)}</td><td style=\"padding:2px 0;{style}\">{E(value)}</td></tr>");
        }
        html.Append("</table>");

        if (rows.Count > 0 && columns.Count > 0)
        {
            html.Append(CultureInfo.InvariantCulture, $"<table style=\"border-collapse:collapse;{Mono}margin-bottom:16px\"><tr>");
            foreach (var column in columns)
            {
                html.Append(CultureInfo.InvariantCulture, $"<th style=\"text-align:left;padding:4px 10px;border-bottom:2px solid #d5dce4;{Font}font-size:12px\">{E(column)}</th>");
            }
            html.Append("</tr>");
            foreach (var row in rows)
            {
                html.Append("<tr>");
                foreach (var value in row)
                {
                    var text = AlertEvaluator.Text(value);
                    if (text.Length > 300)
                    {
                        text = text[..300] + "…";
                    }
                    html.Append(CultureInfo.InvariantCulture, $"<td style=\"padding:3px 10px;border-bottom:1px solid #e6ebf0;vertical-align:top\">{E(text)}</td>");
                }
                html.Append("</tr>");
            }
            html.Append("</table>");
        }

        if (searchLink is not null || historyLink is not null)
        {
            html.Append("<p style=\"margin:0\">");
            if (searchLink is not null)
            {
                html.Append(CultureInfo.InvariantCulture, $"<a href=\"{E(searchLink)}\" style=\"color:#1f5fa8\">{(rule.Kind == AlertRuleKind.Search ? "Open the search" : "Open Health")}</a>");
            }
            if (historyLink is not null)
            {
                html.Append(CultureInfo.InvariantCulture, $"{(searchLink is null ? "" : " &nbsp;·&nbsp; ")}<a href=\"{E(historyLink)}\" style=\"color:#1f5fa8\">Alert history</a>");
            }
            html.Append("</p>");
        }
        html.Append("<p style=\"margin-top:20px;color:#8796a8;font-size:12px\">Sent by DG SIEM.</p></div>");
        return html.ToString();
    }
}
