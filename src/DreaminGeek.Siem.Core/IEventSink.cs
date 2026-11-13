namespace DreaminGeek.Siem.Core;

/// <summary>Writes batches of normalized events to the event store.</summary>
public interface IEventSink
{
    Task WriteAsync(IReadOnlyList<LogEvent> batch, CancellationToken cancellationToken);
}
