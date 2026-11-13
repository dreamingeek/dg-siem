namespace DreaminGeek.Siem.Core;

/// <summary>Reads any ECS field of a <see cref="LogEvent"/> by name, promoted column or map entry alike.</summary>
public static class LogEventFields
{
    public static string? Get(LogEvent e, string ecsName)
    {
        ArgumentNullException.ThrowIfNull(e);
        return ecsName switch
        {
            EcsField.Message => e.Message,
            EcsField.HostName => e.HostName,
            EcsField.ObserverIp => e.ObserverIp,
            EcsField.EventDataset => e.EventDataset,
            EcsField.EventModule => e.EventModule,
            EcsField.EventAction => e.EventAction,
            EcsField.EventOutcome => e.EventOutcome,
            EcsField.LogLevel => e.LogLevel,
            EcsField.SourceIp => e.SourceIp,
            EcsField.SourcePort => e.SourcePort == 0 ? string.Empty : e.SourcePort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            EcsField.DestinationIp => e.DestinationIp,
            EcsField.DestinationPort => e.DestinationPort == 0 ? string.Empty : e.DestinationPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            EcsField.NetworkProtocol => e.NetworkProtocol,
            EcsField.NetworkTransport => e.NetworkTransport,
            EcsField.UserName => e.UserName,
            "raw" => e.Raw,
            _ => e.Fields.GetValueOrDefault(ecsName),
        };
    }
}
