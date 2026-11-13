using DreaminGeek.Siem.Core;

namespace DreaminGeek.Siem.Parsers;

/// <summary>Runs registered parsers in priority order; the first successful parse wins.</summary>
public sealed class ParserRegistry
{
    private const string UnparsedDataset = "unparsed";

    private readonly IEventParser[] _parsers;

    public ParserRegistry(IEnumerable<IEventParser> parsers) =>
        _parsers = parsers.OrderBy(p => p.Priority).ToArray();

    public IReadOnlyList<IEventParser> Parsers => _parsers;

    public LogEvent Parse(RawEnvelope envelope, string tenantId)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var parsed = envelope.Input == HecEvents.Input ? ParseHec(envelope, tenantId) : ParseCore(envelope, tenantId);
        // The agent's file input names the file it read: ECS log.file.path.
        if (envelope.Input.StartsWith("file:", StringComparison.Ordinal) && envelope.Input.Length > 5)
        {
            parsed.Fields.TryAdd("log.file.path", envelope.Input[5..]);
        }
        return parsed;
    }

    /// <summary>An event from the agent's HTTP Event Collector: unwrap it, parse the line inside, add the HEC metadata.</summary>
    private LogEvent ParseHec(RawEnvelope envelope, string tenantId)
    {
        if (!HecEvents.TryRead(envelope.Message, out var hec, out var document) || hec is null)
        {
            return ParseCore(envelope, tenantId);
        }
        using (document)
        {
            var time = hec.Time ?? envelope.ReceivedAt;
            // A hint only when someone named one: a syslog line with no sourcetype is still "syslog".
            var hint = envelope.DatasetHint ?? HecEvents.DatasetFor(hec.SourceType);
            LogEvent parsed;
            if (HecEvents.Line(hec.Event) is { } line)
            {
                parsed = ParseCore(new RawEnvelope(time, HecEvents.Input, envelope.SourceAddress, line, hint), tenantId);
                if (parsed.EventDataset == UnparsedDataset)
                {
                    parsed.EventDataset = HecEvents.Dataset;
                }
                HecEvents.AddDockerFields(hec.Event, parsed);
            }
            else
            {
                parsed = HecEvents.FromObject(hec.Event, tenantId, time, envelope.SourceAddress, hint ?? HecEvents.Dataset);
            }
            HecEvents.ApplyMetadata(hec, parsed);
            return parsed;
        }
    }

    private LogEvent ParseCore(RawEnvelope envelope, string tenantId)
    {
        foreach (var parser in _parsers)
        {
            if (parser.CanParse(envelope) && parser.TryParse(envelope, tenantId, out var parsed) && parsed is not null)
            {
                return parsed;
            }
        }

        // Nothing matched: keep the line, searchable by its raw text.
        return new LogEvent
        {
            TenantId = tenantId,
            Timestamp = envelope.ReceivedAt,
            ObserverIp = envelope.SourceAddress ?? string.Empty,
            EventDataset = envelope.DatasetHint ?? UnparsedDataset,
            Message = envelope.Message,
            Raw = envelope.Message,
        };
    }
}
