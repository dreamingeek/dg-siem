using System.Globalization;

namespace DreaminGeek.Siem.Parsers.Formats;

/// <summary>
/// A Linux netfilter/iptables log line, e.g.
/// <c>[WAN_IN-D-3000] IN=eth8 OUT=br0 MAC=.. SRC=203.0.113.9 DST=192.168.1.5 PROTO=TCP SPT=51515 DPT=443 SYN</c>.
/// </summary>
public sealed record KernelFirewallRecord(string? Rule, IReadOnlyDictionary<string, string> Fields, IReadOnlySet<string> Flags);

public static class KernelFirewall
{
    /// <summary>True if the line has the SRC/DST/PROTO markers of a netfilter log.</summary>
    public static bool Looks(string message) =>
        message.Contains(" SRC=", StringComparison.Ordinal) &&
        message.Contains(" DST=", StringComparison.Ordinal) &&
        message.Contains("PROTO=", StringComparison.Ordinal);

    public static KernelFirewallRecord Parse(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        string? rule = null;
        var body = message.AsSpan();

        var open = message.IndexOf('[', StringComparison.Ordinal);
        var firstKv = message.IndexOf(" IN=", StringComparison.Ordinal);
        if (open >= 0 && (firstKv < 0 || open < firstKv))
        {
            var close = message.IndexOf(']', open);
            if (close > open)
            {
                rule = message[(open + 1)..close];
                body = message.AsSpan(close + 1);
            }
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        var i = 0;
        while (i < body.Length)
        {
            while (i < body.Length && body[i] == ' ')
            {
                i++;
            }
            var start = i;
            while (i < body.Length && body[i] is not ' ' and not '=')
            {
                i++;
            }
            var key = body[start..i].ToString();
            if (i < body.Length && body[i] == '=')
            {
                i++;
                string value;
                if (i < body.Length && body[i] == '"')
                {
                    var end = body[(i + 1)..].IndexOf('"');
                    end = end < 0 ? body.Length : i + 1 + end;
                    value = body[(i + 1)..end].ToString();
                    i = Math.Min(end + 1, body.Length);
                }
                else
                {
                    var vs = i;
                    while (i < body.Length && body[i] != ' ')
                    {
                        i++;
                    }
                    value = body[vs..i].ToString();
                }
                fields[key] = value;
            }
            else if (key.Length > 0)
            {
                flags.Add(key);
            }
        }

        return new KernelFirewallRecord(rule, fields, flags);
    }

    /// <summary>
    /// Maps a UniFi-style rule name to an action: <c>WAN_IN-D-3000</c> → drop,
    /// <c>LAN_LOCAL-A-2000</c> → accept, <c>…-R-…</c> → reject, <c>…-RET-…</c> → return.
    /// </summary>
    public static string? ActionFromRule(string? rule)
    {
        if (string.IsNullOrEmpty(rule))
        {
            return null;
        }
        foreach (var part in rule.Split('-'))
        {
            switch (part)
            {
                case "A": return "accept";
                case "D": return "drop";
                case "R": return "reject";
                case "RET": return "return";
            }
        }
        return null;
    }

    public static ushort Port(IReadOnlyDictionary<string, string> fields, string key) =>
        fields.TryGetValue(key, out var v) && ushort.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : (ushort)0;
}
