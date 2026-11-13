using System.Formats.Tar;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Ingest.GeoIp;

namespace DreaminGeek.Siem.Web.GeoIp;

/// <summary>What the GeoIP page shows.</summary>
public sealed record GeoIpStatus(
    GeoIpProvider Provider, IReadOnlyList<GeoIpDatabaseInfo> Databases, DateTimeOffset? LastCheck, DateTimeOffset? LastUpdate,
    string? LastError, long Lookups, long Enriched, string Directory);

/// <summary>
/// Keeps the GeoIP databases current: downloads DB-IP Lite (monthly) or MaxMind GeoLite2 (weekly), or loads
/// files you put in the folder; validates each download before swapping it in without a restart.
/// Files live in <c>GeoIp:Directory</c> (default <c>/var/lib/dg-siem/geoip</c>, on the data volume).
/// </summary>
public sealed partial class GeoIpUpdater(
    GeoIpEnricher enricher,
    SettingsStore settings,
    IHttpClientFactory httpFactory,
    IConfiguration configuration,
    TimeProvider time,
    ILogger<GeoIpUpdater> logger) : BackgroundService
{
    public const string HttpClientName = "geoip";
    public const string CityFile = "city.mmdb";
    public const string AsnFile = "asn.mmdb";
    private static readonly TimeSpan CheckEvery = TimeSpan.FromHours(6);
    private static readonly TimeSpan MaxMindMaxAge = TimeSpan.FromDays(7);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private GeoIpProvider _provider = GeoIpProvider.Off;
    private DateTimeOffset? _lastCheck;
    private DateTimeOffset? _lastUpdate;
    private string? _lastError;
    private DateTime _localStamp;

    public string Directory { get; } = configuration.GetValue("GeoIp:Directory", "/var/lib/dg-siem/geoip")!;

    public GeoIpProvider Provider => _provider;

    public GeoIpStatus Status => new(_provider, enricher.Loaded, _lastCheck, _lastUpdate, _lastError, enricher.Lookups, enricher.Enriched, Directory);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        using var timer = new PeriodicTimer(CheckEvery);
        do
        {
            try
            {
                await RefreshAsync(force: false, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogFailed(logger, ex);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>Applies the settings: loads what's on disk and downloads when due (or <paramref name="force"/>).</summary>
    public async Task RefreshAsync(bool force, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var config = await settings.GetGeoIpAsync(ct);
            _provider = config.Provider;
            enricher.EnrichDestination = config.EnrichDestination;
            _lastCheck = time.GetUtcNow();
            if (config.Provider == GeoIpProvider.Off)
            {
                enricher.Unload();
                _lastError = null;
                return;
            }

            System.IO.Directory.CreateDirectory(Directory);
            var city = Path.Combine(Directory, CityFile);
            var asn = Path.Combine(Directory, AsnFile);

            if (config.Provider == GeoIpProvider.LocalFiles)
            {
                var stamp = new[] { city, asn }.Where(File.Exists).Select(File.GetLastWriteTimeUtc).DefaultIfEmpty().Max();
                if (stamp == default)
                {
                    enricher.Unload();
                    _lastError = $"Put {CityFile} and/or {AsnFile} in {Directory}.";
                    return;
                }
                if (force || stamp != _localStamp || !enricher.IsLoaded)
                {
                    enricher.Load(File.Exists(city) ? city : null, File.Exists(asn) ? asn : null);
                    _localStamp = stamp;
                    _lastUpdate = time.GetUtcNow();
                }
                _lastError = null;
                return;
            }

            // Load what's already downloaded so enrichment works while (or if) the update below fails.
            if (!enricher.IsLoaded && (File.Exists(city) || File.Exists(asn)))
            {
                enricher.Load(File.Exists(city) ? city : null, File.Exists(asn) ? asn : null);
            }

            if (force || IsDue(config.Provider, city) || IsDue(config.Provider, asn))
            {
                if (config.Provider == GeoIpProvider.DbIpLite)
                {
                    await DownloadDbIpAsync("city", city, ct);
                    await DownloadDbIpAsync("asn", asn, ct);
                }
                else
                {
                    await DownloadMaxMindAsync(config, "GeoLite2-City", city, ct);
                    await DownloadMaxMindAsync(config, "GeoLite2-ASN", asn, ct);
                }
                enricher.Load(city, asn);
                _lastUpdate = time.GetUtcNow();
                LogUpdated(logger, config.Provider);
            }
            _lastError = null;
        }
        catch (GeoIpDownloadException ex)
        {
            _lastError = ex.Message;
            LogDownloadFailed(logger, ex.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>DB-IP publishes at the start of each month; MaxMind twice a week (we take weekly).</summary>
    private bool IsDue(GeoIpProvider provider, string path)
    {
        if (!File.Exists(path))
        {
            return true;
        }
        var now = time.GetUtcNow();
        if (provider == GeoIpProvider.MaxMind)
        {
            return now - File.GetLastWriteTimeUtc(path) > MaxMindMaxAge;
        }
        try
        {
            var built = GeoIpEnricher.Inspect(path, "check").BuildDate;
            return built.Year != now.Year || built.Month != now.Month;
        }
        catch (MaxMind.Db.InvalidDatabaseException)
        {
            return true;
        }
    }

    private async Task DownloadDbIpAsync(string kind, string target, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        // This month's file appears in the first days of the month; until then use last month's.
        foreach (var month in new[] { now, now.AddMonths(-1) })
        {
            var url = new Uri(string.Create(CultureInfo.InvariantCulture, $"https://download.db-ip.com/free/dbip-{kind}-lite-{month:yyyy-MM}.mmdb.gz"));
            using var response = await Send(new HttpRequestMessage(HttpMethod.Get, url), ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                continue;
            }
            Ensure(response, "DB-IP");
            await using var gzip = new GZipStream(await response.Content.ReadAsStreamAsync(ct), CompressionMode.Decompress);
            await SaveValidatedAsync(gzip, target, kind, ct);
            return;
        }
        throw new GeoIpDownloadException($"DB-IP has no {kind} database for this or last month yet.");
    }

    private async Task DownloadMaxMindAsync(GeoIpSettings config, string edition, string target, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(config.MaxMindAccountId) || string.IsNullOrEmpty(config.MaxMindLicenseKey))
        {
            throw new GeoIpDownloadException("Enter your MaxMind account ID and license key.");
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{config.MaxMindAccountId}:{config.MaxMindLicenseKey}")));
        using var response = await Send(request, ct);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new GeoIpDownloadException("MaxMind rejected the account ID or license key.");
        }
        Ensure(response, "MaxMind");
        await using var gzip = new GZipStream(await response.Content.ReadAsStreamAsync(ct), CompressionMode.Decompress);
        await using var tar = new TarReader(gzip);
        while (await tar.GetNextEntryAsync(copyData: false, ct) is { } entry)
        {
            if (entry.Name.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase) && entry.DataStream is { } data)
            {
                await SaveValidatedAsync(data, target, edition.Contains("ASN", StringComparison.Ordinal) ? "asn" : "city", ct);
                return;
            }
        }
        throw new GeoIpDownloadException($"The {edition} download had no .mmdb file in it.");
    }

    /// <summary>Writes to a temp file, checks it opens as the right kind of database, then replaces the old one.</summary>
    private static async Task SaveValidatedAsync(Stream data, string target, string kind, CancellationToken ct)
    {
        var temp = target + ".download";
        await using (var file = File.Create(temp))
        {
            await data.CopyToAsync(file, ct);
        }
        try
        {
            var info = GeoIpEnricher.Inspect(temp, kind);
            var expected = kind == "asn" ? "ASN" : "City";
            if (!info.DatabaseType.Contains(expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new GeoIpDownloadException($"Expected a {expected} database but got \"{info.DatabaseType}\".");
            }
        }
        catch (MaxMind.Db.InvalidDatabaseException ex)
        {
            File.Delete(temp);
            throw new GeoIpDownloadException($"The downloaded {kind} database is damaged: {ex.Message}");
        }
        // On Linux the running reader keeps the old file mapped until it's swapped out.
        File.Move(temp, target, overwrite: true);
    }

    private async Task<HttpResponseMessage> Send(HttpRequestMessage request, CancellationToken ct)
    {
        try
        {
            using (request)
            {
                return await httpFactory.CreateClient(HttpClientName).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            }
        }
        catch (HttpRequestException ex)
        {
            throw new GeoIpDownloadException($"Couldn't reach {request.RequestUri?.Host}: {ex.Message}");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new GeoIpDownloadException($"{request.RequestUri?.Host} didn't answer in time.");
        }
    }

    private static void Ensure(HttpResponseMessage response, string source)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new GeoIpDownloadException($"{source} download failed: {(int)response.StatusCode} {response.StatusCode}.");
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "GeoIP databases updated ({Provider})")]
    private static partial void LogUpdated(ILogger logger, GeoIpProvider provider);

    [LoggerMessage(Level = LogLevel.Warning, Message = "GeoIP update failed: {Reason}")]
    private static partial void LogDownloadFailed(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Error, Message = "GeoIP update pass failed")]
    private static partial void LogFailed(ILogger logger, Exception ex);
}

public sealed class GeoIpDownloadException(string message) : Exception(message);
