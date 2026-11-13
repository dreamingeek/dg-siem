using System.Text;

namespace DreaminGeek.Siem.Parsers.Formats;

/// <summary>A parsed ArcSight CEF record: <c>CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension</c>.</summary>
public sealed record CefRecord(
    string Version, string DeviceVendor, string DeviceProduct, string DeviceVersion,
    string SignatureId, string Name, string Severity, IReadOnlyDictionary<string, string> Extensions);

/// <summary>CEF parser handling the header's <c>\|</c> escapes and the extension's <c>\=</c>, <c>\\</c>, <c>\n</c> escapes and spaces in values.</summary>
public static class Cef
{
    /// <summary>Finds <c>CEF:</c> anywhere in the line (it usually follows a syslog header) and parses from there.</summary>
    public static bool TryParse(string line, out CefRecord? record)
    {
        record = null;
        var start = (line ?? string.Empty).IndexOf("CEF:", StringComparison.Ordinal);
        if (start < 0)
        {
            return false;
        }

        var text = line!.AsSpan(start + 4);
        var header = new string[7];
        var field = new StringBuilder();
        var index = 0;
        var i = 0;
        for (; i < text.Length && index < 7; i++)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length && text[i + 1] is '|' or '\\')
            {
                field.Append(text[++i]);
            }
            else if (c == '|')
            {
                header[index++] = field.ToString();
                field.Clear();
            }
            else
            {
                field.Append(c);
            }
        }
        if (index < 7)
        {
            return false;
        }

        record = new CefRecord(header[0], header[1], header[2], header[3], header[4], header[5], header[6], ParseExtension(text[i..]));
        return true;
    }

    /// <summary>Parses <c>k1=v1 k2=value with spaces k3=v3</c>. A key is a run of word characters followed by an unescaped '='.</summary>
    public static Dictionary<string, string> ParseExtension(ReadOnlySpan<char> text)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        string? key = null;
        var value = new StringBuilder();
        var i = 0;

        while (i < text.Length)
        {
            // At a token boundary: is this "key=" ?
            if ((i == 0 || text[i - 1] == ' ') && TryReadKey(text, i, out var nextKey, out var afterKey))
            {
                if (key is not null)
                {
                    result[key] = value.ToString().TrimEnd();
                }
                key = nextKey;
                value.Clear();
                i = afterKey;
                continue;
            }

            var c = text[i];
            if (c == '\\' && i + 1 < text.Length)
            {
                var n = text[i + 1];
                value.Append(n switch { 'n' => '\n', 'r' => '\r', _ => n });
                i += 2;
                continue;
            }
            value.Append(c);
            i++;
        }

        if (key is not null)
        {
            result[key] = value.ToString().TrimEnd();
        }
        return result;
    }

    private static bool TryReadKey(ReadOnlySpan<char> text, int start, out string key, out int afterEquals)
    {
        var j = start;
        while (j < text.Length && (char.IsAsciiLetterOrDigit(text[j]) || text[j] is '_' or '.' or '-'))
        {
            j++;
        }
        if (j > start && j < text.Length && text[j] == '=')
        {
            key = text[start..j].ToString();
            afterEquals = j + 1;
            return true;
        }
        key = string.Empty;
        afterEquals = start;
        return false;
    }
}
