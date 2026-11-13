using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers;

/// <summary>
/// Turns a raw line into a normalized ECS <see cref="LogEvent"/>. Parsers are discovered by
/// <see cref="ParserRegistry"/>; contributors add a source by implementing this interface.
/// </summary>
public interface IEventParser
{
    /// <summary>The <c>event.dataset</c> this parser produces, e.g. <c>unifi.firewall</c>.</summary>
    string Dataset { get; }

    /// <summary>Lower runs first. Generic fallbacks (plain syslog) use a high number.</summary>
    int Priority { get; }

    /// <summary>Cheap check: can this parser handle the line? Must not allocate heavily.</summary>
    bool CanParse(RawEnvelope envelope);

    /// <summary>Parse the line. Return <c>false</c> to fall through to the next parser.</summary>
    bool TryParse(RawEnvelope envelope, string tenantId, out LogEvent? logEvent);
}
