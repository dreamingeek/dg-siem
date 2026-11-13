using System.Globalization;
using System.Text;

namespace DreaminGeek.Siem.Query;

public enum TokenKind
{
    Word,      // field names, barewords, keywords (AND/OR/NOT/IN/by/as), numbers in search mode
    Number,    // expression mode only
    Quoted,    // "quoted" or 'quoted'
    Op,        // = != < <= > >= ( ) , + - * / % .
    End,
}

public readonly record struct Token(TokenKind Kind, string Text, int Position)
{
    public bool Is(string text) => Kind is TokenKind.Op or TokenKind.Word && string.Equals(Text, text, StringComparison.Ordinal);

    /// <summary>Keyword match, case-insensitive (e.g. <c>by</c>, <c>BY</c>).</summary>
    public bool IsKeyword(string keyword) => Kind == TokenKind.Word && string.Equals(Text, keyword, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Tokenizer with two modes. <b>Search mode</b> (the leading clause) treats almost anything
/// unquoted as one bareword, so <c>10.0.0.5</c>, <c>AP-01</c> and <c>*fail*</c> work unquoted.
/// <b>Expression mode</b> (where/eval/...) splits on operators, so <c>bytes*8</c> is arithmetic and
/// <c>a . b</c> is concatenation; field names may still contain dots (<c>source.ip</c>).
/// </summary>
public static class Lexer
{
    public static List<Token> Tokenize(string text, int offset, bool searchMode)
    {
        ArgumentNullException.ThrowIfNull(text);
        var tokens = new List<Token>();
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            if (char.IsWhiteSpace(c))
            {
                i++;
                continue;
            }

            var start = i;
            if (c is '"' or '\'')
            {
                tokens.Add(new Token(TokenKind.Quoted, ReadString(text, ref i, offset), offset + start));
                continue;
            }

            // Two-char operators first.
            if (i + 1 < text.Length && text.Substring(i, 2) is "!=" or "<=" or ">=" or "==")
            {
                var op = text.Substring(i, 2);
                tokens.Add(new Token(TokenKind.Op, op == "==" ? "=" : op, offset + start));
                i += 2;
                continue;
            }

            if (searchMode)
            {
                if (c is '=' or '<' or '>' or '(' or ')' or ',')
                {
                    tokens.Add(new Token(TokenKind.Op, c.ToString(), offset + start));
                    i++;
                    continue;
                }
                while (i < text.Length && !char.IsWhiteSpace(text[i]) && text[i] is not ('=' or '<' or '>' or '(' or ')' or ',' or '"' or '\'') &&
                       !(text[i] == '!' && i + 1 < text.Length && text[i + 1] == '='))
                {
                    i++;
                }
                tokens.Add(new Token(TokenKind.Word, text[start..i], offset + start));
                continue;
            }

            // Expression mode.
            if (char.IsAsciiDigit(c) || (c == '.' && i + 1 < text.Length && char.IsAsciiDigit(text[i + 1]) && !PrevIsValue(tokens)))
            {
                while (i < text.Length && (char.IsAsciiDigit(text[i]) || text[i] == '.'))
                {
                    i++;
                }
                // A digit-led run followed by letters is a word like "5m" (spans) or an odd field name.
                if (i < text.Length && (char.IsAsciiLetter(text[i]) || text[i] == '_'))
                {
                    while (i < text.Length && IsWordChar(text[i]))
                    {
                        i++;
                    }
                    tokens.Add(new Token(TokenKind.Word, text[start..i], offset + start));
                }
                else
                {
                    tokens.Add(new Token(TokenKind.Number, text[start..i], offset + start));
                }
                continue;
            }
            if (IsWordStart(c))
            {
                while (i < text.Length && (IsWordChar(text[i]) || (text[i] == '.' && i + 1 < text.Length && IsWordChar(text[i + 1]))))
                {
                    i++;
                }
                tokens.Add(new Token(TokenKind.Word, text[start..i], offset + start));
                continue;
            }
            if (c is '=' or '<' or '>' or '(' or ')' or ',' or '+' or '-' or '*' or '/' or '%' or '.')
            {
                tokens.Add(new Token(TokenKind.Op, c.ToString(), offset + start));
                i++;
                continue;
            }
            throw new QueryParseException($"Unexpected character '{c}'.", offset + start);
        }
        tokens.Add(new Token(TokenKind.End, string.Empty, offset + text.Length));
        return tokens;
    }

    /// <summary>Splits a query into pipeline segments on '|' outside quotes. Returns (text, absolute offset).</summary>
    public static List<(string Text, int Offset)> SplitPipes(string query)
    {
        ArgumentNullException.ThrowIfNull(query);
        var segments = new List<(string, int)>();
        var start = 0;
        char? quote = null;
        for (var i = 0; i < query.Length; i++)
        {
            var c = query[i];
            if (quote is not null)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == quote)
                {
                    quote = null;
                }
            }
            else if (c is '"' or '\'')
            {
                quote = c;
            }
            else if (c == '|')
            {
                segments.Add((query[start..i], start));
                start = i + 1;
            }
        }
        if (quote is not null)
        {
            throw new QueryParseException("Unterminated quoted string.", query.LastIndexOf(quote.Value));
        }
        segments.Add((query[start..], start));
        return segments;
    }

    public static bool IsWordStart(char c) => char.IsAsciiLetter(c) || c is '_' or '@';

    public static bool IsWordChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or '@';

    private static bool PrevIsValue(List<Token> tokens) =>
        tokens.Count > 0 && (tokens[^1].Kind is TokenKind.Word or TokenKind.Number or TokenKind.Quoted || tokens[^1].Is(")"));

    private static string ReadString(string text, ref int i, int offset)
    {
        var quote = text[i];
        var start = i;
        var sb = new StringBuilder();
        i++;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length)
            {
                var n = text[i + 1];
                // Keep backslashes that aren't escaping a quote or backslash, so regexes like "\d+" survive.
                if (n == quote || n == '\\')
                {
                    sb.Append(n);
                }
                else
                {
                    sb.Append(c).Append(n);
                }
                i += 2;
                continue;
            }
            if (c == quote)
            {
                i++;
                return sb.ToString();
            }
            sb.Append(c);
            i++;
        }
        throw new QueryParseException("Unterminated quoted string.", offset + start);
    }

    public static double ParseNumber(Token token) =>
        double.TryParse(token.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var v)
            ? v
            : throw new QueryParseException($"'{token.Text}' is not a number.", token.Position);
}
