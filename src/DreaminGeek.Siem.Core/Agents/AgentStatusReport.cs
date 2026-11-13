using System.Globalization;

namespace DreaminGeek.Siem.Core.Agents;

/// <summary>
/// What an agent reports about itself on each config poll, in the <see cref="Header"/> request header:
/// its disk buffer backlog and anything it lost. A plain <c>key=value; ...</c> line rather than JSON, so older
/// servers ignore it and the AOT agent needs no serializer for it.
/// </summary>
/// <param name="PendingBytes">Events waiting in the disk buffer to be sent.</param>
/// <param name="PendingSegments">Buffer files waiting (each up to a few thousand events).</param>
/// <param name="OldestPending">How long the oldest waiting buffer file has waited; null when nothing waits.</param>
/// <param name="Dropped">Events dropped since the agent started because its queue was full.</param>
/// <param name="Evicted">Events deleted since the agent started because the buffer hit its size cap.</param>
/// <param name="Rejected">Buffer files the server refused, set aside in buffer/rejected.</param>
public sealed record AgentStatusReport(long PendingBytes, int PendingSegments, TimeSpan? OldestPending, long Dropped, long Evicted, int Rejected)
{
    public const string Header = "X-DGSIEM-Agent-Status";

    public string Format() => string.Create(CultureInfo.InvariantCulture,
        $"pending-bytes={PendingBytes}; pending-segments={PendingSegments}; oldest-seconds={(OldestPending is { } o ? (long)o.TotalSeconds : -1)}; dropped={Dropped}; evicted={Evicted}; rejected={Rejected}");

    /// <summary>Null for a missing or unreadable header. Unknown keys are ignored, so agents can add more later.</summary>
    public static AgentStatusReport? Parse(string? header)
    {
        if (string.IsNullOrWhiteSpace(header) || header.Length > 1024)
        {
            return null;
        }
        var values = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in header.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0 && long.TryParse(part[(eq + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value))
            {
                values[part[..eq].Trim()] = value;
            }
        }
        if (!values.ContainsKey("pending-bytes"))
        {
            return null;
        }
        long Get(string key) => Math.Max(0, values.GetValueOrDefault(key));
        var oldest = values.GetValueOrDefault("oldest-seconds", -1);
        return new AgentStatusReport(
            Get("pending-bytes"), (int)Math.Min(int.MaxValue, Get("pending-segments")),
            oldest >= 0 ? TimeSpan.FromSeconds(oldest) : null,
            Get("dropped"), Get("evicted"), (int)Math.Min(int.MaxValue, Get("rejected")));
    }
}
