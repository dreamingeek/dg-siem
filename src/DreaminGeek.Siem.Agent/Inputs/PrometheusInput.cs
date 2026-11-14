using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>
/// A Prometheus scrape job: every interval, fetch each target's metrics page and ship it as it is, with a header
/// line saying how long it took or why it failed (<see cref="MetricScrape"/>). The server parses the samples, as it
/// does log lines, and adds <c>up</c>, so a target that stops answering shows up as <c>up=0</c>.
/// </summary>
public sealed partial class PrometheusInput(InputConfig config, DiskBuffer buffer, ILogger logger) : IDisposable
{
    /// <summary>For tests: called instead of the buffer when set.</summary>
    internal Func<RawEnvelope, bool>? Emit { get; init; }

    /// <summary>For tests: the handler requests go through.</summary>
    internal HttpMessageHandler? Handler { get; init; }

    private HttpClient? _client;

    public TimeSpan Interval => Duration(config.ScrapeInterval, TimeSpan.FromMinutes(1));

    private TimeSpan Timeout
    {
        get
        {
            var timeout = Duration(config.ScrapeTimeout, TimeSpan.FromSeconds(10));
            return timeout < Interval ? timeout : Interval;
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var job = config.Job ?? "prometheus";
        var targets = config.Targets ?? [];
        LogStarted(logger, job, targets.Count, Interval.TotalSeconds);
        using var timer = new PeriodicTimer(Interval);
        do
        {
            await ScrapeAllAsync(ct);
        }
        while (await timer.WaitForNextTickAsync(ct));
    }

    /// <summary>Scrapes every target once, in parallel.</summary>
    public Task ScrapeAllAsync(CancellationToken ct) =>
        Task.WhenAll((config.Targets ?? []).Select(target => ScrapeAsync(target, ct)));

    private async Task ScrapeAsync(string target, CancellationToken ct)
    {
        var job = config.Job ?? "prometheus";
        var started = DateTimeOffset.UtcNow;
        var clock = Stopwatch.StartNew();
        string message;
        try
        {
            var body = await FetchAsync(target, ct);
            message = string.Create(CultureInfo.InvariantCulture, $"{MetricScrape.HeaderPrefix}duration_seconds={clock.Elapsed.TotalSeconds:0.######}\n") + body;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or InvalidDataException)
        {
            var reason = ex is TaskCanceledException ? $"timed out after {Timeout.TotalSeconds:0.#}s" : ex.GetBaseException().Message;
            message = MetricScrape.HeaderPrefix + "error=" + reason.ReplaceLineEndings(" ");
            LogScrapeFailed(logger, job, target, reason);
        }
        var envelope = new RawEnvelope(started, MetricScrape.InputPrefix + job, target, message);
        if (!(Emit?.Invoke(envelope) ?? buffer.TryEnqueue(envelope)))
        {
            LogDropped(logger, job, target);
        }
    }

    private async Task<string> FetchAsync(string target, CancellationToken ct)
    {
        var url = $"{config.Scheme ?? "http"}://{target}{config.MetricsPath ?? "/metrics"}";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        // Plain text, as Prometheus itself asks for when protobuf is off.
        request.Headers.Accept.ParseAdd("text/plain;version=0.0.4;q=1");
        request.Headers.Accept.ParseAdd("application/openmetrics-text;version=1.0.0;q=0.5");
        request.Headers.Accept.ParseAdd("*/*;q=0.1");
        request.Headers.UserAgent.ParseAdd("dg-siem-agent");
        if (config.Authorization is { Credentials: { } credentials } auth)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(auth.Type ?? "Bearer", credentials);
        }
        else if (config.BasicAuth is { } basic)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{basic.Username}:{basic.Password}")));
        }

        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"server returned HTTP status {(int)response.StatusCode} {response.ReasonPhrase}");
        }
        if (response.Content.Headers.ContentLength > MetricScrape.MaxBytes)
        {
            throw new InvalidDataException($"the metrics page is over {MetricScrape.MaxBytes / 1024 / 1024} MB");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var copy = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, timeout.Token)) > 0)
        {
            if (copy.Length + read > MetricScrape.MaxBytes)
            {
                throw new InvalidDataException($"the metrics page is over {MetricScrape.MaxBytes / 1024 / 1024} MB");
            }
            copy.Write(chunk, 0, read);
        }
        return Encoding.UTF8.GetString(copy.GetBuffer(), 0, (int)copy.Length);
    }

    private HttpClient Client => _client ??= new HttpClient(Handler ?? CreateHandler(), disposeHandler: true)
    {
        Timeout = System.Threading.Timeout.InfiniteTimeSpan, // per scrape, above
    };

    private SocketsHttpHandler CreateHandler()
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = Timeout,
        };
        if (config.InsecureSkipVerify)
        {
            // Only when the admin asks for it (insecureSkipVerify), as Prometheus' tls_config allows.
#pragma warning disable CA5359
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
#pragma warning restore CA5359
        }
        return handler;
    }

    private static TimeSpan Duration(string? text, TimeSpan fallback) =>
        MetricScrape.TryParseDuration(text, out var duration) && duration > TimeSpan.Zero ? duration : fallback;

    public void Dispose() => _client?.Dispose();

    [LoggerMessage(Level = LogLevel.Information, Message = "Prometheus job {Job}: scraping {Targets} target(s) every {Seconds}s")]
    private static partial void LogStarted(ILogger logger, string job, int targets, double seconds);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Prometheus job {Job}: scraping {Target} failed: {Reason}")]
    private static partial void LogScrapeFailed(ILogger logger, string job, string target, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Prometheus job {Job}: buffer full, dropped the scrape of {Target}")]
    private static partial void LogDropped(ILogger logger, string job, string target);
}
