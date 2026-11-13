using DreaminGeek.Siem.Data.Entities;

namespace DreaminGeek.Siem.Alerting;

/// <summary>
/// Evaluates the health kinds of alert rule (<see cref="AlertRuleKind.QuietSources"/>, <see cref="AlertRuleKind.AgentProblems"/>)
/// for one tenant. The result goes through the same suppression, email, tickets and history as a search alert.
/// Implemented by the web server, which knows the agents and sources.
/// </summary>
public interface IHealthAlertSource
{
    Task<AlertEvaluation> EvaluateAsync(AlertRule rule, string tenant, DateTimeOffset now, CancellationToken ct);
}

/// <summary>Used where no health checks are available (the admin CLI): health rules find nothing.</summary>
public sealed class NoHealthAlerts : IHealthAlertSource
{
    public Task<AlertEvaluation> EvaluateAsync(AlertRule rule, string tenant, DateTimeOffset now, CancellationToken ct) =>
        Task.FromResult(new AlertEvaluation(0, false, false, [], [], []));
}
