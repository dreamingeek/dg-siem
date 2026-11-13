namespace DreaminGeek.Siem.Core;

/// <summary>Wire contract for <c>POST /api/v1/ingest</c>: a batch of raw lines from one agent.</summary>
/// <param name="AgentId">Enrolled agent identifier. In Phase 1 this comes from the agent's mTLS certificate, not the body.</param>
/// <param name="Events">Raw lines captured by the agent.</param>
public sealed record IngestBatch(string AgentId, IReadOnlyList<RawEnvelope> Events);
