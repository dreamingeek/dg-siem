using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Server;

public enum ShipResult
{
    Accepted,
    /// <summary>Server rejected the batch itself (bad data, too large): set it aside, don't retry forever.</summary>
    Rejected,
    /// <summary>Not allowed (revoked, unknown cert): keep data, back off, alert loudly.</summary>
    Unauthorized,
    /// <summary>Network or server trouble: keep data, retry with backoff.</summary>
    Retry,
}

/// <summary>mTLS HTTP client for the agent API. Rebuilt after certificate renewal.</summary>
public sealed class ServerClient : IDisposable
{
    public static readonly string Version = BuildInfo.Version;

    /// <summary><c>linux-x64</c>, <c>linux-arm64</c>, <c>win-x64</c>: which update package fits this agent.</summary>
    public static string Platform =>
        (OperatingSystem.IsWindows() ? "win" : "linux") + "-" +
        (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64");

    private readonly Lock _gate = new();
    private readonly AgentStore _store;
    private HttpClient _http;

    public ServerClient(AgentStore store)
    {
        _store = store;
        _http = Build(store);
    }

    public Uri ServerUrl { get; private set; } = null!;

    public X509Certificate2 ClientCertificate { get; private set; } = null!;

    private HttpClient Http
    {
        get
        {
            lock (_gate)
            {
                return _http;
            }
        }
    }

    /// <summary>Reload certificate files (after renewal).</summary>
    public void Reload()
    {
        var fresh = Build(_store);
        lock (_gate)
        {
            // Don't dispose the old client: in-flight requests may still use it. It is small and GC'd.
            _http = fresh;
        }
    }

    /// <summary>The agent's config; <paramref name="status"/> tells the server about this agent's backlog (Health page).</summary>
    public async Task<AgentConfig?> GetConfigAsync(AgentStatusReport? status, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "api/v1/agent/config");
        if (status is not null)
        {
            request.Headers.TryAddWithoutValidation(AgentStatusReport.Header, status.Format());
        }
        using var response = await Http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync(AgentJsonContext.Default.AgentConfig, ct);
    }

    /// <summary>A newer version for this platform, or null when this one is current (or updates are off).</summary>
    public async Task<AgentUpdateInfo?> GetUpdateAsync(CancellationToken ct)
    {
        using var response = await Http.GetAsync($"api/v1/agent/update?platform={Uri.EscapeDataString(Platform)}", ct);
        if (response.StatusCode == HttpStatusCode.NoContent)
        {
            return null;
        }
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync(AgentJsonContext.Default.AgentUpdateInfo, ct);
    }

    /// <summary>Streams the update's binary into <paramref name="destination"/>.</summary>
    public async Task DownloadUpdateAsync(AgentUpdateInfo update, Stream destination, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(update);
        using var response = await Http.GetAsync(
            $"api/v1/agent/update/binary?platform={Uri.EscapeDataString(update.Platform)}&version={Uri.EscapeDataString(update.Version)}",
            HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        await body.CopyToAsync(destination, ct);
    }

    public async Task<string> RenewAsync(string csrPem, CancellationToken ct)
    {
        using var response = await Http.PostAsJsonAsync("api/v1/agent/renew", new RenewRequest(csrPem), AgentJsonContext.Default.RenewRequest, ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync(AgentJsonContext.Default.RenewResponse, ct);
        return body?.CertificatePem ?? throw new HttpRequestException("Empty renewal response.");
    }

    /// <summary>Sends a pre-built, gzip-compressed <see cref="AgentIngestBatch"/> JSON body.</summary>
    public async Task<(ShipResult Result, HttpStatusCode? Status)> ShipAsync(byte[] gzipJson, CancellationToken ct)
    {
        using var content = new ByteArrayContent(gzipJson);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        try
        {
            using var response = await Http.PostAsync("api/v1/agent/ingest", content, ct);
            var status = response.StatusCode;
            return ((int)status) switch
            {
                >= 200 and < 300 => (ShipResult.Accepted, status),
                401 or 403 => (ShipResult.Unauthorized, status),
                400 or 413 or 415 or 422 => (ShipResult.Rejected, status),
                _ => (ShipResult.Retry, status),
            };
        }
        catch (HttpRequestException)
        {
            return (ShipResult.Retry, null);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return (ShipResult.Retry, null); // timeout
        }
    }

    /// <summary>Gzip helper for batch bodies.</summary>
    public static byte[] Gzip(ReadOnlySpan<byte> json)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest))
        {
            gzip.Write(json);
        }
        return output.ToArray();
    }

    private HttpClient Build(AgentStore store)
    {
        var (serverUrl, _, _) = store.LoadState();
        var clientCert = store.LoadClientCertificate();
        var ca = store.LoadCa();
        ServerUrl = serverUrl;
        ClientCertificate = clientCert;
        return CreateHttpClient(serverUrl, h =>
        {
            h.SslOptions.ClientCertificates = [clientCert];
            h.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, errors) => CaPinning.Validate(ca, cert, errors);
        });
    }

    internal static HttpClient CreateHttpClient(Uri serverUrl, Action<SocketsHttpHandler> configure)
    {
        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            ConnectTimeout = TimeSpan.FromSeconds(15),
            AutomaticDecompression = DecompressionMethods.All,
        };
        configure(handler);
        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri(serverUrl.ToString().TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(60),
        };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("dg-siem-agent", Version));
        return http;
    }

    public void Dispose() => _http.Dispose();
}
