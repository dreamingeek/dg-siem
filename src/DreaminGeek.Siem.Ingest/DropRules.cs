using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Ingest;

public enum DropMatch
{
    /// <summary>Drop every event in the dataset (no field condition).</summary>
    Any,
    Equals,
    Contains,
    StartsWith,
    Regex,
}

/// <summary>
/// "Never store events like this." Evaluated after parsing, before storage.
/// <c>Dataset</c> matches exactly, or as a prefix when it ends in <c>*</c> (e.g. <c>unifi.*</c>).
/// </summary>
public sealed record DropRule(
    Guid Id, string Name, string? TenantSlug, string? Dataset, string? Field, DropMatch Match, string? Value);

/// <summary>Source of the current drop rules (the server loads them from PostgreSQL).</summary>
public interface IDropRuleSource
{
    IReadOnlyList<DropRule> Current { get; }

    /// <summary>Called with how many events each rule dropped since the last call.</summary>
    void Report(IReadOnlyDictionary<Guid, long> droppedByRule);
}

/// <summary>Compiled, thread-safe view of the rules with per-rule drop counters.</summary>
public sealed class DropFilter(IDropRuleSource source)
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);
    private readonly ConcurrentDictionary<Guid, long> _dropped = new();
    private readonly ConcurrentDictionary<(Guid, string), Regex> _regexes = new();

    /// <summary>The rule that drops this event, or null to keep it.</summary>
    public DropRule? Match(LogEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        foreach (var rule in source.Current)
        {
            if (Matches(rule, e))
            {
                _dropped.AddOrUpdate(rule.Id, 1, static (_, n) => n + 1);
                return rule;
            }
        }
        return null;
    }

    /// <summary>Hands the counters to the source and resets them.</summary>
    public void Flush()
    {
        var snapshot = new Dictionary<Guid, long>();
        foreach (var id in _dropped.Keys)
        {
            if (_dropped.TryRemove(id, out var n) && n > 0)
            {
                snapshot[id] = n;
            }
        }
        if (snapshot.Count > 0)
        {
            source.Report(snapshot);
        }
    }

    private bool Matches(DropRule rule, LogEvent e)
    {
        if (rule.TenantSlug is not null && !string.Equals(rule.TenantSlug, e.TenantId, StringComparison.Ordinal))
        {
            return false;
        }
        if (rule.Dataset is { Length: > 0 } dataset)
        {
            var ok = dataset.EndsWith('*')
                ? e.EventDataset.StartsWith(dataset[..^1], StringComparison.Ordinal)
                : string.Equals(e.EventDataset, dataset, StringComparison.Ordinal);
            if (!ok)
            {
                return false;
            }
        }
        if (rule.Match == DropMatch.Any || rule.Field is null)
        {
            return true;
        }

        var actual = LogEventFields.Get(e, rule.Field);
        if (actual is null)
        {
            return false;
        }
        var expected = rule.Value ?? string.Empty;
        return rule.Match switch
        {
            DropMatch.Equals => string.Equals(actual, expected, StringComparison.Ordinal),
            DropMatch.Contains => actual.Contains(expected, StringComparison.Ordinal),
            DropMatch.StartsWith => actual.StartsWith(expected, StringComparison.Ordinal),
            DropMatch.Regex => RegexMatches(rule, expected, actual),
            _ => false,
        };
    }

    private bool RegexMatches(DropRule rule, string pattern, string actual)
    {
        var regex = _regexes.GetOrAdd((rule.Id, pattern), static key =>
            new Regex(key.Item2, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, RegexTimeout));
        try
        {
            return regex.IsMatch(actual);
        }
        catch (RegexMatchTimeoutException)
        {
            return false; // never drop on a pathological match
        }
    }
}

/// <summary>No rules: used when nothing registers a real source (tests, tools).</summary>
public sealed class NoDropRules : IDropRuleSource
{
    public IReadOnlyList<DropRule> Current => [];

    public void Report(IReadOnlyDictionary<Guid, long> droppedByRule)
    {
    }
}
