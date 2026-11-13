using System.Text;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>
/// Splits a syslog TCP stream into messages (RFC 6587). Each frame is either octet-counted
/// (<c>"57 &lt;34&gt;1 ..."</c>) or terminated by LF or NUL. The method is chosen per frame, since
/// some senders mix them.
/// </summary>
public sealed class SyslogFrameDecoder(int maxMessageBytes = 64 * 1024)
{
    private byte[] _buffer = new byte[16 * 1024];
    private int _length;

    /// <summary>Messages that were too long and cut at <c>maxMessageBytes</c>.</summary>
    public long Truncated { get; private set; }

    /// <summary>Feeds bytes; returns every complete message they finish.</summary>
    public List<string> Feed(ReadOnlySpan<byte> data)
    {
        EnsureCapacity(_length + data.Length);
        data.CopyTo(_buffer.AsSpan(_length));
        _length += data.Length;

        var messages = new List<string>();
        var start = 0;
        while (start < _length)
        {
            var span = _buffer.AsSpan(start, _length - start);
            var octet = TryOctetCounted(span, out var consumed, out var message);
            if (octet == Frame.Complete || (octet == Frame.NotThisKind && TryDelimited(span, out consumed, out message)))
            {
                start += consumed;
                if (message is { Length: > 0 })
                {
                    messages.Add(message);
                }
                continue;
            }

            // Incomplete frame. If it's already oversized, emit what we have so memory stays bounded.
            if (span.Length >= maxMessageBytes + 16)
            {
                messages.Add(Decode(span[..maxMessageBytes]));
                Truncated++;
                start += maxMessageBytes;
                continue;
            }
            break;
        }

        // Shift the unconsumed tail to the front.
        _buffer.AsSpan(start, _length - start).CopyTo(_buffer);
        _length -= start;
        return messages;
    }

    /// <summary>Whatever is left when the connection closes (a final line without a newline).</summary>
    public string? Flush()
    {
        if (_length == 0)
        {
            return null;
        }
        var message = Decode(_buffer.AsSpan(0, _length));
        _length = 0;
        return message.Length > 0 ? message : null;
    }

    private enum Frame
    {
        NotThisKind,
        Incomplete,
        Complete,
    }

    private Frame TryOctetCounted(ReadOnlySpan<byte> span, out int consumed, out string? message)
    {
        consumed = 0;
        message = null;
        if (span.Length == 0 || span[0] is < (byte)'1' or > (byte)'9')
        {
            return Frame.NotThisKind;
        }

        var limit = Math.Min(span.Length, 8);
        var length = 0;
        for (var i = 0; i < limit; i++)
        {
            var b = span[i];
            if (b == (byte)' ')
            {
                if (length > maxMessageBytes)
                {
                    return Frame.NotThisKind;
                }
                if (span.Length < i + 1 + length)
                {
                    return Frame.Incomplete; // wait for the rest; never split it on embedded newlines
                }
                message = Decode(span.Slice(i + 1, length));
                consumed = i + 1 + length;
                return Frame.Complete;
            }
            if (b is < (byte)'0' or > (byte)'9')
            {
                return Frame.NotThisKind;
            }
            length = (length * 10) + (b - '0');
        }
        // Only digits so far: could still become a length prefix.
        return span.Length < 8 ? Frame.Incomplete : Frame.NotThisKind;
    }

    private static bool TryDelimited(ReadOnlySpan<byte> span, out int consumed, out string? message)
    {
        var end = span.IndexOfAny((byte)'\n', (byte)'\0');
        if (end < 0)
        {
            consumed = 0;
            message = null;
            return false;
        }
        message = Decode(span[..end]);
        consumed = end + 1;
        return true;
    }

    private static string Decode(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes).TrimEnd('\r', '\n', '\0', ' ');

    private void EnsureCapacity(int needed)
    {
        if (needed > _buffer.Length)
        {
            Array.Resize(ref _buffer, Math.Max(needed, _buffer.Length * 2));
        }
    }
}
