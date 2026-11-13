using DreaminGeek.Siem.Data.Entities;

namespace DreaminGeek.Siem.Web.Alerts;

/// <summary>Display helpers shared by the alert pages.</summary>
public static class AlertUi
{
    public static string SeverityClass(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => "dg-sev dg-sev-critical",
        AlertSeverity.High => "dg-sev dg-sev-error",
        AlertSeverity.Medium => "dg-sev dg-sev-warning",
        _ => "dg-sev dg-sev-notice",
    };

    public static string StatusText(AlertFiringStatus status) => status switch
    {
        AlertFiringStatus.Sent => "Sent",
        AlertFiringStatus.Partial => "Partly failed",
        AlertFiringStatus.Failed => "Failed",
        _ => "Recorded",
    };

    public static string StatusDot(AlertFiringStatus status) => status switch
    {
        AlertFiringStatus.Sent => "dg-dot dg-dot-ok",
        AlertFiringStatus.Partial => "dg-dot dg-dot-warn",
        AlertFiringStatus.Failed => "dg-dot dg-dot-bad",
        _ => "dg-dot dg-dot-off",
    };

    /// <summary>"in 3 min", "in 2 h" for the next run.</summary>
    public static string Until(DateTimeOffset? when)
    {
        if (when is null)
        {
            return "—";
        }
        var span = when.Value - DateTimeOffset.UtcNow;
        return span.TotalSeconds < 60 ? "within a minute"
            : span.TotalMinutes < 60 ? $"in {(int)span.TotalMinutes} min"
            : span.TotalHours < 48 ? $"in {(int)span.TotalHours} h"
            : $"in {(int)span.TotalDays} days";
    }
}
