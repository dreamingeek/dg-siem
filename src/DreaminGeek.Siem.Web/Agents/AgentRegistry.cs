using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace DreaminGeek.Siem.Web.Agents;

/// <summary>The identity behind a validated agent certificate.</summary>
public sealed record AgentIdentity(Guid AgentId, string Name, Guid TenantId, string TenantSlug);

public sealed class EnrollmentException(string message) : Exception(message);

/// <summary>Enrollment, renewal, config and identity lookup for collector agents.</summary>
public sealed partial class AgentRegistry(
    IDbContextFactory<SiemDbContext> dbFactory,
    CertificateAuthority ca,
    IMemoryCache cache,
    ILogger<AgentRegistry> logger)
{
    private static readonly TimeSpan IdentityCacheTime = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan LastSeenWriteInterval = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> _lastSeenWritten = new();
    private readonly ConcurrentDictionary<Guid, (AgentStatusReport Report, DateTimeOffset At)> _status = new();

    /// <summary>Keeps the backlog an agent reported on its config poll (agents 0.5+). In memory: refreshed every minute.</summary>
    public void ReportStatus(Guid agentId, AgentStatusReport? report)
    {
        if (report is not null)
        {
            _status[agentId] = (report, DateTimeOffset.UtcNow);
        }
    }

    /// <summary>The agent's latest report and when it came, or null if it hasn't reported since the server started.</summary>
    public (AgentStatusReport Report, DateTimeOffset At)? GetStatus(Guid agentId) =>
        _status.TryGetValue(agentId, out var status) ? status : null;

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!EnrollmentTokenFormat.TryParse(request.Token, out var secret, out var pinned))
        {
            throw new EnrollmentException("Malformed enrollment token.");
        }
        if (!string.Equals(pinned, ca.CaFingerprint, StringComparison.Ordinal))
        {
            throw new EnrollmentException("Token was issued by a different DG SIEM server.");
        }
        var name = request.Name?.Trim() ?? string.Empty;
        if (name.Length is 0 or > 63 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_'))
        {
            throw new EnrollmentException("Agent name must be 1-63 letters, digits, '-', '.' or '_'.");
        }
        if (ca.IsServerName(name))
        {
            throw new EnrollmentException($"'{name}' is the server's own name; pick another agent name.");
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var hash = EnrollmentTokenFormat.HashSecret(secret);
        var token = await db.EnrollmentTokens.Include(t => t.Tenant).SingleOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (token is null || token.UsedAt is not null || token.ExpiresAt < DateTimeOffset.UtcNow)
        {
            throw new EnrollmentException("Enrollment token is invalid, expired or already used.");
        }
        if (token.AgentName is not null && !string.Equals(token.AgentName, name, StringComparison.OrdinalIgnoreCase))
        {
            throw new EnrollmentException($"This token can only enroll an agent named '{token.AgentName}'.");
        }

        // Re-enrolling an existing name replaces its certificate but keeps its config. Only a token made for
        // that name may do it, so a general token can't take over an agent, and a revoked agent stays revoked.
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.TenantId == token.TenantId && a.Name == name, ct);
        if (agent is not null && token.AgentName is null)
        {
            throw new EnrollmentException($"An agent named '{name}' already exists. To re-enroll it, create a token for that agent name.");
        }
        if (agent?.RevokedAt is not null)
        {
            throw new EnrollmentException($"Agent '{name}' is revoked. Restore or delete it first.");
        }
        if (agent is null)
        {
            agent = new CollectorAgent
            {
                Id = Guid.NewGuid(),
                TenantId = token.TenantId,
                Name = name,
                ConfigJson = JsonSerializer.Serialize(AgentConfig.DefaultFor(request.Platform), AgentJsonContext.Default.AgentConfig),
            };
            db.Agents.Add(agent);
        }

        using var cert = ca.IssueAgentCertificate(request.CsrPem, agent.Id, name, token.Tenant.Slug);
        agent.CertificateThumbprint = CertificateAuthority.Thumbprint(cert);
        agent.CertificateNotAfter = cert.NotAfter.ToUniversalTime();
        agent.Version = request.Version;
        agent.LastSeenAt = DateTimeOffset.UtcNow;

        // Claim the token atomically so two enrollments racing on one token can't both succeed.
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var now = DateTimeOffset.UtcNow;
        var claimed = await db.EnrollmentTokens
            .Where(t => t.Id == token.Id && t.UsedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.UsedAt, now), ct);
        if (claimed != 1)
        {
            throw new EnrollmentException("Enrollment token is invalid, expired or already used.");
        }
        db.Entry(token).State = EntityState.Unchanged;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);

        LogEnrolled(logger, name, token.Tenant.Slug, agent.Id);
        return new EnrollResponse(agent.Id, token.Tenant.Slug, cert.ExportCertificatePem(), ca.CaCertificatePem, ParseConfig(agent.ConfigJson));
    }

    public async Task<RenewResponse> RenewAsync(AgentIdentity identity, RenewRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(request);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.SingleAsync(a => a.Id == identity.AgentId, ct);
        using var cert = ca.IssueAgentCertificate(request.CsrPem, agent.Id, agent.Name, identity.TenantSlug);
        var oldThumbprint = agent.CertificateThumbprint;
        agent.CertificateThumbprint = CertificateAuthority.Thumbprint(cert);
        agent.CertificateNotAfter = cert.NotAfter.ToUniversalTime();
        await db.SaveChangesAsync(ct);
        if (oldThumbprint is not null)
        {
            cache.Remove(CacheKey(oldThumbprint));
        }
        LogRenewed(logger, agent.Name, identity.TenantSlug);
        return new RenewResponse(cert.ExportCertificatePem());
    }

    public async Task<AgentConfig> GetConfigAsync(AgentIdentity identity, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var json = await db.Agents.Where(a => a.Id == identity.AgentId).Select(a => a.ConfigJson).SingleAsync(ct);
        return ParseConfig(json);
    }

    /// <summary>Maps a CA-validated certificate to its agent. Null if unknown, replaced or revoked.</summary>
    public async Task<AgentIdentity?> ResolveAsync(X509Certificate2 certificate, CancellationToken ct)
    {
        var thumbprint = CertificateAuthority.Thumbprint(certificate);
        if (cache.TryGetValue(CacheKey(thumbprint), out AgentIdentity? cached))
        {
            return cached;
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var identity = await db.Agents
            .Where(a => a.CertificateThumbprint == thumbprint && a.RevokedAt == null)
            .Select(a => new AgentIdentity(a.Id, a.Name, a.TenantId, a.Tenant.Slug))
            .SingleOrDefaultAsync(ct);
        cache.Set(CacheKey(thumbprint), identity, IdentityCacheTime);
        return identity;
    }

    /// <summary>Records that the agent checked in; writes to the database at most once a minute per agent.</summary>
    public async Task TouchAsync(AgentIdentity identity, string? version, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var now = DateTimeOffset.UtcNow;
        if (_lastSeenWritten.TryGetValue(identity.AgentId, out var last) && now - last < LastSeenWriteInterval)
        {
            return;
        }
        _lastSeenWritten[identity.AgentId] = now;
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Agents.Where(a => a.Id == identity.AgentId)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.LastSeenAt, now).SetProperty(a => a.Version, a => version ?? a.Version), ct);
    }

    /// <summary>Records which update package fits this agent (shown on the Agents page).</summary>
    public async Task SetPlatformAsync(AgentIdentity identity, string platform, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Agents.Where(a => a.Id == identity.AgentId && a.Platform != platform)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Platform, platform), ct);
    }

    /// <summary>
    /// An unused, unexpired enrollment token from this server: enough to download the install package.
    /// Checking doesn't use the token up; enrolling does.
    /// </summary>
    public async Task<bool> IsDownloadTokenValidAsync(string token, CancellationToken ct)
    {
        if (!EnrollmentTokenFormat.TryParse(token, out var secret, out var pinned) || !string.Equals(pinned, ca.CaFingerprint, StringComparison.Ordinal))
        {
            return false;
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var hash = EnrollmentTokenFormat.HashSecret(secret);
        var now = DateTimeOffset.UtcNow;
        return await db.EnrollmentTokens.AnyAsync(t => t.TokenHash == hash && t.UsedAt == null && t.ExpiresAt > now, ct);
    }

    public static AgentConfig ParseConfig(string json) =>
        JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentConfig) ?? new AgentConfig();

    private static string CacheKey(string thumbprint) => "agent-cert:" + thumbprint;

    [LoggerMessage(Level = LogLevel.Information, Message = "Enrolled agent {Name} for tenant {Tenant} ({AgentId})")]
    private static partial void LogEnrolled(ILogger logger, string name, string tenant, Guid agentId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Renewed certificate for agent {Name} ({Tenant})")]
    private static partial void LogRenewed(ILogger logger, string name, string tenant);
}
