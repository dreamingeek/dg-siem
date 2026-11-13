namespace DreaminGeek.Siem.Core;

/// <summary>
/// A raw, unparsed log line as captured by a collector agent. Agents stay "dumb":
/// they only stamp receive time, where it came from and which input caught it.
/// Parsing happens on the server.
/// </summary>
/// <param name="ReceivedAt">When the agent received the line (UTC).</param>
/// <param name="Input">Agent input that captured it, e.g. <c>syslog-udp</c>, <c>hec</c>, <c>file</c>.</param>
/// <param name="SourceAddress">Network peer that sent the line, if any (e.g. the UniFi gateway).</param>
/// <param name="Message">The raw line, unmodified.</param>
/// <param name="DatasetHint">Optional sourcetype hint from agent config, e.g. <c>unifi</c>.</param>
public sealed record RawEnvelope(
    DateTimeOffset ReceivedAt,
    string Input,
    string? SourceAddress,
    string Message,
    string? DatasetHint = null);
