using System.Net;
using System.Text.Json;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Ingest.ThreatIntel;
using DreaminGeek.Siem.Web.Admin;

namespace DreaminGeek.Siem.Web.ThreatIntel;

/// <summary>A feed as the Threat intel page shows it.</summary>
/// <param name="Custom">Added by URL (can be removed); otherwise built in.</param>
public sealed record ThreatFeedStatus(
    string Id, string Name, string Url, bool Enabled, bool Custom, string About, string? TermsUrl, string? Caution,
    int Entries, DateTimeOffset? Downloaded, DateTimeOffset? LastAttempt, string? Error, TimeSpan Interval);

/// <summary>
/// Threat intel (Administration &gt; Threat intel, when switched on under Features): downloads the enabled feeds on
/// their schedules, keeps a copy of each on disk so a restart doesn't wait for downloads, and hands the ingest
/// enricher one index of everything (your own list first). Switched off, it downloads nothing and events aren't marked.
/// </summary>
public sealed partial class ThreatIntelService(
    SettingsStore settings,
    DreaminGeek.Siem.Web.Features.FeatureState features,
    ThreatIntelEnricher enricher,
    IHttpClientFactory httpFactory,
    IConfiguration configuration,
    ILogger<ThreatIntelService> logger) : BackgroundService
{
    public const string HttpClientName = "threatintel";
    private const long MaxDownloadBytes = 50L * 1024 * 1024;
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(15);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly SemaphoreSlim _wake = new(0);
    private readonly Lock _gate = new();
    private readonly Dictionary<string, FeedState> _feeds = new(StringComparer.Ordinal);

    private sealed class FeedState
    {
        public List<ThreatIndicator> Indicators { get; set; } = [];
        public bool Loaded { get; set; }
        public DateTimeOffset? Downloaded { get; set; }
        public DateTimeOffset? LastAttempt { get; set; }
        public string? Error { get; set; }
        public string? ETag { get; set; }
        public DateTimeOffset? LastModified { get; set; }
        public bool Force { get; set; }
    }

    private sealed record CacheFile(DateTimeOffset Downloaded, string? ETag, DateTimeOffset? LastModified, List<ThreatIndicator> Indicators);

    public string Directory { get; } = configuration.GetValue("ThreatIntel:Directory", "/var/lib/dg-siem/threatintel")!;

    public bool IsOn => enricher.IsOn;

    /// <summary>Every feed with its state, built-in first.</summary>
    public async Task<IReadOnlyList<ThreatFeedStatus>> GetFeedsAsync(CancellationToken ct)
    {
        var config = await settings.GetThreatIntelAsync(ct);
        lock (_gate)
        {
            return Definitions(config).Select(d =>
            {
                var state = _feeds.GetValueOrDefault(d.Definition.Id);
                return new ThreatFeedStatus(d.Definition.Id, d.Definition.Name, d.Definition.Url, d.Enabled, d.Custom, d.Definition.About,
                    d.Custom ? null : d.Definition.TermsUrl, d.Definition.Caution, state?.Indicators.Count ?? 0, state?.Downloaded, state?.LastAttempt,
                    state?.Error, d.Definition.Interval);
            }).ToList();
        }
    }

    /// <summary>What an address is listed on right now (null when it isn't, or threat intel is off).</summary>
    public ThreatMatch? Check(string ip) => enricher.Lookup(ip.Trim());

    // ---- Changes from the pages ---------------------------------------------------------------

    public async Task SetEnabledAsync(bool on, CancellationToken ct)
    {
        var current = await features.GetAsync(ct);
        await features.SaveAsync(current with { ThreatIntel = on }, ct);
        LogSwitched(logger, on ? "on" : "off");
        Wake();
    }

    public async Task SetFeedEnabledAsync(string id, bool enabled, CancellationToken ct)
    {
        var config = await settings.GetThreatIntelAsync(ct);
        if (config.Custom.Any(c => c.Id == id))
        {
            config = config with { Custom = config.Custom.Select(c => c.Id == id ? c with { Enabled = enabled } : c).ToList() };
        }
        else if (ThreatFeeds.BuiltIn.Any(b => b.Id == id))
        {
            config = config with { Feeds = new Dictionary<string, bool>(config.Feeds) { [id] = enabled } };
        }
        else
        {
            throw new AdminException("No such feed.");
        }
        await settings.SaveThreatIntelAsync(config, ct);
        Wake();
    }

    public async Task AddFeedAsync(string name, string url, CancellationToken ct)
    {
        name = name?.Trim() ?? string.Empty;
        url = url?.Trim() ?? string.Empty;
        if (name.Length is 0 or > 60)
        {
            throw new AdminException("Give the feed a name (up to 60 characters).");
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
        {
            throw new AdminException("Enter the list's address, starting with https://.");
        }
        var config = await settings.GetThreatIntelAsync(ct);
        if (config.Custom.Any(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase)) || ThreatFeeds.BuiltIn.Any(b => string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            throw new AdminException("There's already a feed with that name.");
        }
        var feed = new CustomThreatFeed($"custom-{Guid.NewGuid():N}"[..15], name, url, true);
        await settings.SaveThreatIntelAsync(config with { Custom = [.. config.Custom, feed] }, ct);
        Wake();
    }

    public async Task RemoveFeedAsync(string id, CancellationToken ct)
    {
        var config = await settings.GetThreatIntelAsync(ct);
        await settings.SaveThreatIntelAsync(config with { Custom = config.Custom.Where(c => c.Id != id).ToList() }, ct);
        lock (_gate)
        {
            _feeds.Remove(id);
        }
        TryDelete(CachePath(id));
        Wake();
    }

    /// <summary>Downloads a feed now (a feed with a daily limit, like Spamhaus DROP, at most once an hour).</summary>
    public void UpdateNow(string id)
    {
        lock (_gate)
        {
            if (!_feeds.TryGetValue(id, out var state))
            {
                _feeds[id] = state = new FeedState();
            }
            state.Force = true;
        }
        Wake();
    }

    /// <summary>Adds addresses or ranges to your own list: one per line, anything after the address is the note.</summary>
    public async Task<int> AddOwnAsync(string lines, string note, string by, CancellationToken ct)
    {
        var parsed = new List<OwnThreatEntry>();
        foreach (var raw in (lines ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = raw.Split([' ', '\t', ','], 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (!ThreatIndex.TryParse(parts[0], out _, out _))
            {
                throw new AdminException($"\"{parts[0]}\" isn't an address or a range like 203.0.113.0/24.");
            }
            var lineNote = parts.Length > 1 ? parts[1] : note?.Trim() ?? string.Empty;
            parsed.Add(new OwnThreatEntry(parts[0], lineNote, DateTimeOffset.UtcNow, by));
        }
        if (parsed.Count == 0)
        {
            throw new AdminException("Enter an address or range.");
        }
        var config = await settings.GetThreatIntelAsync(ct);
        var keep = config.Own.Where(o => !parsed.Any(p => string.Equals(p.Value, o.Value, StringComparison.OrdinalIgnoreCase)));
        await settings.SaveThreatIntelAsync(config with { Own = [.. keep, .. parsed] }, ct);
        Wake();
        return parsed.Count;
    }

    public async Task RemoveOwnAsync(string value, CancellationToken ct)
    {
        var config = await settings.GetThreatIntelAsync(ct);
        await settings.SaveThreatIntelAsync(config with { Own = config.Own.Where(o => !string.Equals(o.Value, value, StringComparison.Ordinal)).ToList() }, ct);
        Wake();
    }

    // ---- Background ---------------------------------------------------------------------------

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogFailed(logger, ex.Message);
            }
            try
            {
                // Check schedules every minute, or straight away after a change on the pages.
                await _wake.WaitAsync(TimeSpan.FromMinutes(1), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>One pass: off → clear the index; on → download what's due and rebuild the index.</summary>
    internal async Task RunOnceAsync(CancellationToken ct)
    {
        if (!(await features.GetAsync(ct)).ThreatIntel)
        {
            if (enricher.IsOn)
            {
                enricher.Use(null);
            }
            return;
        }
        var config = await settings.GetThreatIntelAsync(ct);
        var now = DateTimeOffset.UtcNow;
        foreach (var (definition, enabled, _) in Definitions(config))
        {
            if (!enabled)
            {
                continue;
            }
            var state = State(definition.Id);
            if (!state.Loaded)
            {
                await LoadCacheAsync(definition, state, ct);
            }
            var due = state.Force
                ? state.Downloaded is null || now - state.Downloaded >= TimeSpan.FromMinutes(definition.Interval >= TimeSpan.FromDays(1) ? 60 : 1)
                : state.Error is not null
                    ? now - state.LastAttempt >= RetryAfterFailure
                    : state.Downloaded is null || now - state.Downloaded >= definition.Interval;
            state.Force = false;
            if (due)
            {
                await DownloadAsync(definition, state, now, ct);
            }
        }
        Rebuild(config);
    }

    private void Rebuild(ThreatIntelSettings config)
    {
        var indicators = new List<ThreatIndicator>();
        indicators.AddRange(config.Own.Select(o => new ThreatIndicator(o.Value, ThreatFeeds.OwnListName, o.Note.Length > 0 ? o.Note : "On your list")));
        lock (_gate)
        {
            foreach (var (definition, enabled, _) in Definitions(config))
            {
                if (enabled && _feeds.TryGetValue(definition.Id, out var state))
                {
                    indicators.AddRange(state.Indicators);
                }
            }
        }
        enricher.Use(ThreatIndex.Build(indicators));
    }

    private async Task DownloadAsync(ThreatFeedDefinition definition, FeedState state, DateTimeOffset now, CancellationToken ct)
    {
        state.LastAttempt = now;
        var url = configuration[$"ThreatIntel:Urls:{definition.Id}"] ?? definition.Url;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (state.ETag is not null)
            {
                request.Headers.TryAddWithoutValidation("If-None-Match", state.ETag);
            }
            if (state.LastModified is { } since)
            {
                request.Headers.IfModifiedSince = since;
            }
            using var response = await httpFactory.CreateClient(HttpClientName).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                lock (_gate)
                {
                    state.Downloaded = now;
                    state.Error = null;
                }
                return;
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new ThreatFeedException($"{new Uri(url).Host} answered {(int)response.StatusCode} {response.ReasonPhrase}.");
            }
            if (response.Content.Headers.ContentLength > MaxDownloadBytes)
            {
                throw new ThreatFeedException("The list is over 50 MB; that isn't an address list.");
            }
            var content = await response.Content.ReadAsStringAsync(ct);
            var parsed = ThreatFeeds.Parse(definition.Format, content, definition.Name, definition.EntryDescription);
            if (parsed.Count == 0 && definition.Format == ThreatFeedFormat.PlainText && content.Length > 0 && !content.TrimStart().StartsWith('#'))
            {
                throw new ThreatFeedException("No addresses in the download. Is the address right?");
            }
            var merged = Merge(definition, state.Indicators, parsed, now);
            var etag = response.Headers.ETag?.ToString();
            var modified = response.Content.Headers.LastModified;
            await SaveCacheAsync(definition.Id, new CacheFile(now, etag, modified, merged), ct);
            lock (_gate)
            {
                state.Indicators = merged;
                state.Downloaded = now;
                state.ETag = etag;
                state.LastModified = modified;
                state.Error = null;
            }
            LogDownloaded(logger, definition.Name, merged.Count);
        }
        catch (Exception ex) when (ex is HttpRequestException or ThreatFeedException or FormatException or IOException or UriFormatException
                                       || (ex is TaskCanceledException && !ct.IsCancellationRequested))
        {
            var message = ex is TaskCanceledException ? $"{definition.Name} didn't answer in time." : ex.Message;
            lock (_gate)
            {
                state.Error = message;
            }
            LogDownloadFailed(logger, definition.Name, message);
        }
    }

    /// <summary>
    /// Feeds of recent sightings (ThreatFox) are merged with what was kept, each address dropped
    /// <see cref="ThreatFeedDefinition.KeepDays"/> after it was last seen. Others replace the old list.
    /// </summary>
    public static List<ThreatIndicator> Merge(ThreatFeedDefinition definition, List<ThreatIndicator> kept, List<ThreatIndicator> downloaded, DateTimeOffset now)
    {
        if (definition.KeepDays <= 0)
        {
            return downloaded;
        }
        var cutoff = now.AddDays(-definition.KeepDays);
        var byValue = new Dictionary<string, ThreatIndicator>(StringComparer.Ordinal);
        foreach (var i in kept.Where(i => (i.LastSeen ?? now) >= cutoff))
        {
            byValue[i.Value] = i;
        }
        foreach (var i in downloaded)
        {
            byValue[i.Value] = i with { LastSeen = i.LastSeen ?? now };
        }
        return byValue.Values.ToList();
    }

    private async Task LoadCacheAsync(ThreatFeedDefinition definition, FeedState state, CancellationToken ct)
    {
        state.Loaded = true;
        try
        {
            if (!File.Exists(CachePath(definition.Id)))
            {
                return;
            }
            await using var file = File.OpenRead(CachePath(definition.Id));
            if (await JsonSerializer.DeserializeAsync<CacheFile>(file, Json, ct) is { } cache)
            {
                lock (_gate)
                {
                    state.Indicators = cache.Indicators;
                    state.Downloaded = cache.Downloaded;
                    state.ETag = cache.ETag;
                    state.LastModified = cache.LastModified;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            LogDownloadFailed(logger, definition.Name, $"couldn't read the saved copy: {ex.Message}");
        }
    }

    private async Task SaveCacheAsync(string id, CacheFile cache, CancellationToken ct)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var path = CachePath(id);
        await using (var file = File.Create(path + ".tmp"))
        {
            await JsonSerializer.SerializeAsync(file, cache, Json, ct);
        }
        File.Move(path + ".tmp", path, overwrite: true);
    }

    private string CachePath(string id) => Path.Combine(Directory, $"{id}.json");

    private FeedState State(string id)
    {
        lock (_gate)
        {
            if (!_feeds.TryGetValue(id, out var state))
            {
                _feeds[id] = state = new FeedState();
            }
            return state;
        }
    }

    private static IEnumerable<(ThreatFeedDefinition Definition, bool Enabled, bool Custom)> Definitions(ThreatIntelSettings config) =>
        ThreatFeeds.BuiltIn.Select(b => (b, config.Feeds.TryGetValue(b.Id, out var on) ? on : b.OnByDefault, false))
            .Concat(config.Custom.Select(c => (
                new ThreatFeedDefinition(c.Id, c.Name, c.Url, ThreatFeedFormat.PlainText, TimeSpan.FromHours(6), true,
                    "Added by URL: one address or range per line.", c.Url),
                c.Enabled, true)));

    private void Wake()
    {
        if (_wake.CurrentCount == 0)
        {
            _wake.Release();
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Threat intel switched {State}")]
    private static partial void LogSwitched(ILogger logger, string state);

    [LoggerMessage(Level = LogLevel.Information, Message = "Threat feed {Feed}: {Count} addresses and ranges")]
    private static partial void LogDownloaded(ILogger logger, string feed, int count);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Threat feed {Feed} not updated: {Reason}")]
    private static partial void LogDownloadFailed(ILogger logger, string feed, string reason);

    [LoggerMessage(Level = LogLevel.Error, Message = "Threat intel update failed: {Reason}")]
    private static partial void LogFailed(ILogger logger, string reason);
}

public sealed class ThreatFeedException(string message) : Exception(message);
