using System.Text.Json;
using System.Text.Json.Serialization;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Alerting;

public enum SmtpSecurity
{
    /// <summary>TLS on 465, STARTTLS when the server offers it otherwise.</summary>
    Auto = 0,
    None = 1,
    StartTls = 2,
    SslOnConnect = 3,
}

/// <summary>Outgoing mail through an SMTP relay. Username/password are optional (IP-authorized relays).</summary>
public sealed record SmtpSettings(
    string Host, int Port, SmtpSecurity Security, string? Username, string? Password, string FromAddress, string? FromName)
{
    public bool IsConfigured => Host.Length > 0 && FromAddress.Length > 0;
}

/// <summary>An id and display name from AlgaPSA (board, client, priority).</summary>
public sealed record PsaRef(string Id, string Name);

/// <summary>AlgaPSA connection for alert tickets.</summary>
public sealed record PsaSettings(
    string BaseUrl, string? ApiKey, PsaRef? DefaultBoard, IReadOnlyDictionary<AlertSeverity, PsaRef> Priorities)
{
    public bool IsConfigured => BaseUrl.Length > 0 && !string.IsNullOrEmpty(ApiKey);
}

/// <param name="RequireTwoFactor">Every user must set up an authenticator app before using DG SIEM.</param>
public sealed record GeneralSettings(string? PublicUrl, string TimeZone, bool RequireTwoFactor = false)
{
    /// <summary>The schedule time zone; UTC when the configured one is unknown on this host.</summary>
    [JsonIgnore]
    public TimeZoneInfo Zone => TimeZoneInfo.TryFindSystemTimeZoneById(TimeZone, out var zone) ? zone : TimeZoneInfo.Utc;

    /// <summary>Absolute link into the UI, or null when no public URL is set.</summary>
    public string? Link(string pathAndQuery) =>
        string.IsNullOrWhiteSpace(PublicUrl) ? null : PublicUrl.TrimEnd('/') + "/" + pathAndQuery.TrimStart('/');
}

public enum GeoIpProvider
{
    /// <summary>DB-IP Lite: free, no account, monthly; requires a credit to DB-IP (CC BY 4.0).</summary>
    DbIpLite = 0,
    /// <summary>MaxMind GeoLite2: free account and license key, weekly.</summary>
    MaxMind = 1,
    /// <summary>MMDB files you place in the GeoIP folder yourself (e.g. commercial GeoIP2).</summary>
    LocalFiles = 2,
    Off = 3,
}

/// <param name="MaxMindLicenseKey">Secret; stored encrypted.</param>
/// <param name="EnrichDestination">Also look up destination addresses (outbound traffic).</param>
public sealed record GeoIpSettings(GeoIpProvider Provider, string? MaxMindAccountId, string? MaxMindLicenseKey, bool EnrichDestination = true);

/// <summary>
/// Optional parts of DG SIEM (Administration &gt; Features). Off ones do nothing in the background and are hidden
/// from the menu, so an install can be a plain log collector.
/// </summary>
/// <param name="ThreatIntel">Download threat feeds and mark events from or to listed addresses (off by default: it reaches out to the feeds' sites).</param>
public sealed record FeatureSettings(bool ThreatIntel = false)
{
    public static FeatureSettings Default { get; } = new();
}

/// <summary>A feed added by URL: a plain list of addresses and ranges.</summary>
public sealed record CustomThreatFeed(string Id, string Name, string Url, bool Enabled);

/// <summary>An address or range on your own list, with why.</summary>
public sealed record OwnThreatEntry(string Value, string Note, DateTimeOffset At, string By);

/// <param name="Feeds">Built-in feeds switched on or off (by id); a feed not here uses its default.</param>
public sealed record ThreatIntelSettings(IReadOnlyDictionary<string, bool> Feeds, IReadOnlyList<CustomThreatFeed> Custom, IReadOnlyList<OwnThreatEntry> Own)
{
    public static ThreatIntelSettings Default { get; } = new(new Dictionary<string, bool>(), [], []);
}

/// <summary>A source left out of quiet-source alerts (a retired device), by <c>tenant|dataset|host</c>.</summary>
public sealed record IgnoredSource(string Key, DateTimeOffset At, string By);

/// <summary>Administration &gt; Health.</summary>
public sealed record HealthSettings(IReadOnlyList<IgnoredSource> Ignored)
{
    public static HealthSettings Default { get; } = new([]);

    public bool IsIgnored(string key) => Ignored.Any(i => string.Equals(i.Key, key, StringComparison.Ordinal));
}

/// <summary>The cold tier's S3-compatible bucket (Administration &gt; Storage). The secret is stored encrypted.</summary>
public sealed record ColdStorageSettings(string Endpoint, string AccessKeyId, string? SecretAccessKey);

/// <param name="AutoUpdate">Agents install newer versions uploaded to the server on their own.</param>
public sealed record AgentUpdateSettings(bool AutoUpdate = true);

/// <summary>
/// Server-wide settings edited in the UI, stored in PostgreSQL (<c>AppSettings</c>). Passwords and API keys
/// are encrypted with ASP.NET data protection (the same persisted key ring as the login cookies).
/// </summary>
public sealed class SettingsStore(IDbContextFactory<SiemDbContext> dbFactory, IDataProtectionProvider protection)
{
    private const string SmtpKey = "smtp";
    private const string PsaKey = "algapsa";
    private const string GeneralKey = "general";
    private const string GeoIpKey = "geoip";
    private const string AgentUpdatesKey = "agentupdates";
    private const string RetentionKey = "retention";
    private const string ColdStorageKey = "coldstorage";
    private const string HealthKey = "health";
    private const string FeaturesKey = "features";
    private const string ThreatIntelKey = "threatintel";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly IDataProtector _protector = protection.CreateProtector("DreaminGeek.Siem.Settings.v1");

    public static SmtpSettings EmptySmtp { get; } = new(string.Empty, 25, SmtpSecurity.Auto, null, null, string.Empty, "DG SIEM");
    public static PsaSettings EmptyPsa { get; } = new(string.Empty, null, null, new Dictionary<AlertSeverity, PsaRef>());
    public static GeneralSettings DefaultGeneral { get; } = new(null, "UTC");
    public static GeoIpSettings DefaultGeoIp { get; } = new(GeoIpProvider.DbIpLite, null, null);

    /// <summary>Retention rules and the cold tier; the suggested defaults until an admin saves their own.</summary>
    public async Task<DreaminGeek.Siem.Core.RetentionSettings> GetRetentionAsync(CancellationToken ct) =>
        await ReadAsync<DreaminGeek.Siem.Core.RetentionSettings>(RetentionKey, ct) ?? DreaminGeek.Siem.Core.RetentionSettings.Suggested;

    public Task SaveRetentionAsync(DreaminGeek.Siem.Core.RetentionSettings settings, CancellationToken ct) => WriteAsync(RetentionKey, settings, ct);

    public async Task<FeatureSettings> GetFeaturesAsync(CancellationToken ct) => await ReadAsync<FeatureSettings>(FeaturesKey, ct) ?? FeatureSettings.Default;

    public Task SaveFeaturesAsync(FeatureSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return WriteAsync(FeaturesKey, settings, ct);
    }

    public async Task<ThreatIntelSettings> GetThreatIntelAsync(CancellationToken ct) => await ReadAsync<ThreatIntelSettings>(ThreatIntelKey, ct) ?? ThreatIntelSettings.Default;

    public Task SaveThreatIntelAsync(ThreatIntelSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return WriteAsync(ThreatIntelKey, settings, ct);
    }

    public async Task<HealthSettings> GetHealthAsync(CancellationToken ct) => await ReadAsync<HealthSettings>(HealthKey, ct) ?? HealthSettings.Default;

    public Task SaveHealthAsync(HealthSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return WriteAsync(HealthKey, settings, ct);
    }

    /// <summary>The cold tier's bucket, or null if it isn't set up here.</summary>
    public async Task<ColdStorageSettings?> GetColdStorageAsync(CancellationToken ct)
    {
        var stored = await ReadAsync<ColdStorageSettings>(ColdStorageKey, ct);
        return stored is null ? null : stored with { SecretAccessKey = Unprotect(stored.SecretAccessKey) };
    }

    public Task SaveColdStorageAsync(ColdStorageSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return WriteAsync(ColdStorageKey, settings with { SecretAccessKey = Protect(settings.SecretAccessKey ?? string.Empty) }, ct);
    }

    public async Task<AgentUpdateSettings> GetAgentUpdatesAsync(CancellationToken ct) =>
        await ReadAsync<AgentUpdateSettings>(AgentUpdatesKey, ct) ?? new AgentUpdateSettings();

    public Task SaveAgentUpdatesAsync(AgentUpdateSettings settings, CancellationToken ct) => WriteAsync(AgentUpdatesKey, settings, ct);

    public async Task<GeoIpSettings> GetGeoIpAsync(CancellationToken ct)
    {
        var stored = await ReadAsync<GeoIpSettings>(GeoIpKey, ct);
        return stored is null ? DefaultGeoIp : stored with { MaxMindLicenseKey = Unprotect(stored.MaxMindLicenseKey) };
    }

    /// <param name="settings">A null license key keeps the stored one.</param>
    public async Task SaveGeoIpAsync(GeoIpSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var existing = (await ReadAsync<GeoIpSettings>(GeoIpKey, ct))?.MaxMindLicenseKey;
        await WriteAsync(GeoIpKey, settings with
        {
            MaxMindAccountId = string.IsNullOrWhiteSpace(settings.MaxMindAccountId) ? null : settings.MaxMindAccountId.Trim(),
            MaxMindLicenseKey = settings.MaxMindLicenseKey is null ? existing : Protect(settings.MaxMindLicenseKey.Trim()),
        }, ct);
    }

    public async Task<SmtpSettings> GetSmtpAsync(CancellationToken ct)
    {
        var stored = await ReadAsync<SmtpSettings>(SmtpKey, ct);
        return stored is null ? EmptySmtp : stored with { Password = Unprotect(stored.Password) };
    }

    /// <param name="settings">A null password keeps the stored one.</param>
    public async Task SaveSmtpAsync(SmtpSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var existing = (await ReadAsync<SmtpSettings>(SmtpKey, ct))?.Password;
        var toStore = settings with
        {
            Host = settings.Host.Trim(),
            FromAddress = settings.FromAddress.Trim(),
            Password = settings.Password is null ? existing : Protect(settings.Password),
        };
        await WriteAsync(SmtpKey, toStore, ct);
    }

    public async Task<PsaSettings> GetPsaAsync(CancellationToken ct)
    {
        var stored = await ReadAsync<PsaSettings>(PsaKey, ct);
        return stored is null ? EmptyPsa : stored with { ApiKey = Unprotect(stored.ApiKey) };
    }

    /// <param name="settings">A null API key keeps the stored one.</param>
    public async Task SavePsaAsync(PsaSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var existing = (await ReadAsync<PsaSettings>(PsaKey, ct))?.ApiKey;
        var toStore = settings with
        {
            BaseUrl = settings.BaseUrl.Trim().TrimEnd('/'),
            ApiKey = settings.ApiKey is null ? existing : Protect(settings.ApiKey.Trim()),
        };
        await WriteAsync(PsaKey, toStore, ct);
    }

    public async Task<GeneralSettings> GetGeneralAsync(CancellationToken ct) =>
        await ReadAsync<GeneralSettings>(GeneralKey, ct) ?? DefaultGeneral;

    public Task SaveGeneralAsync(GeneralSettings settings, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return WriteAsync(GeneralKey, settings with { PublicUrl = string.IsNullOrWhiteSpace(settings.PublicUrl) ? null : settings.PublicUrl.Trim().TrimEnd('/') }, ct);
    }

    private string? Protect(string? value) => string.IsNullOrEmpty(value) ? null : _protector.Protect(value);

    private string? Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }
        try
        {
            return _protector.Unprotect(value);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Key ring lost (e.g. /var/lib/dg-siem/keys wiped): treat as unset so the admin re-enters it.
            return null;
        }
    }

    private async Task<T?> ReadAsync<T>(string key, CancellationToken ct) where T : class
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var row = await db.AppSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Key == key, ct);
        return row is null ? null : JsonSerializer.Deserialize<T>(row.Value, Json);
    }

    private async Task WriteAsync<T>(string key, T value, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var json = JsonSerializer.Serialize(value, Json);
        var row = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (row is null)
        {
            db.AppSettings.Add(new AppSetting { Key = key, Value = json });
        }
        else
        {
            row.Value = json;
            row.UpdatedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }
}
