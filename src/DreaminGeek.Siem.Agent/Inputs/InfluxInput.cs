using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>
/// Receives metrics in InfluxDB line protocol over HTTP, as an InfluxDB server would: <c>POST /api/v2/write</c>
/// (Proxmox VE/Backup Server's metric server, Telegraf's influxdb_v2 output) and <c>POST /write</c> (v1). Bodies go
/// into the disk buffer as they are, with a header line giving the timestamp precision; the server parses them
/// (<see cref="MetricPush"/>).
/// </summary>
public sealed partial class InfluxHttpInput(InputConfig config, DiskBuffer buffer, X509Certificate2? tlsCertificate, ILogger logger)
{
    /// <summary>For tests: called instead of the buffer when set.</summary>
    internal Func<RawEnvelope, bool>? Emit { get; init; }

    private readonly byte[][] _tokens = (config.Tokens ?? []).Select(Encoding.UTF8.GetBytes).ToArray();

    public async Task RunAsync(CancellationToken ct)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ApplicationName = "dg-siem-agent" });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = HecInput.MaxBodyBytes;
            void Configure(ListenOptions listen)
            {
                if (config.Tls && tlsCertificate is not null)
                {
                    listen.UseHttps(tlsCertificate);
                }
            }
            if (config.BindAddress is "0.0.0.0" or "" or "*" or "::")
            {
                kestrel.ListenAnyIP(config.Port, Configure);
            }
            else
            {
                kestrel.Listen(IPAddress.Parse(config.BindAddress), config.Port, Configure);
            }
        });
        await using var app = builder.Build();
        app.Run(HandleAsync);
        await app.StartAsync(ct);
        LogListening(logger, config.Tls ? "https" : "http", config.Port);
        try
        {
            await Task.Delay(Timeout.Infinite, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Stopping.
        }
        finally
        {
            await app.StopAsync(CancellationToken.None);
        }
    }

    internal async Task HandleAsync(HttpContext context)
    {
        var path = (context.Request.Path.Value ?? string.Empty).TrimEnd('/');
        switch (path)
        {
            case "/ping" or "/health" or "/api/v2/ping" or "":
                // Connection tests (Proxmox, Telegraf) and load balancer checks.
                context.Response.StatusCode = path == "/health" ? 200 : 204;
                if (path == "/health")
                {
                    await context.Response.WriteAsync("""{"name":"dg-siem-agent","status":"pass"}""", context.RequestAborted);
                }
                return;
            case "/api/v2/write" or "/write":
                break;
            default:
                await Error(context, 404, "not found");
                return;
        }
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await Error(context, 405, "use POST");
            return;
        }
        if (_tokens.Length > 0 && !IsValid(Token(context.Request)))
        {
            await Error(context, 401, "unauthorized access");
            return;
        }

        byte[] body;
        try
        {
            body = await HecInput.ReadBodyAsync(context.Request, context.RequestAborted);
        }
        catch (Exception ex) when (ex is Microsoft.AspNetCore.Http.BadHttpRequestException or InvalidDataException or IOException)
        {
            await Error(context, 400, "invalid or too large body");
            return;
        }
        var precision = MetricPush.Precision(context.Request.Query["precision"].ToString());
        if (precision is null)
        {
            await Error(context, 400, "precision must be ns, us, ms or s");
            return;
        }
        if (body.Length > 0)
        {
            var from = context.Connection.RemoteIpAddress;
            var source = from is null ? null : (from.IsIPv4MappedToIPv6 ? from.MapToIPv4() : from).ToString();
            var envelope = MetricPush.Envelope(config.Job, source, precision, Encoding.UTF8.GetString(body));
            if (!(Emit?.Invoke(envelope) ?? buffer.TryEnqueue(envelope)))
            {
                // Ask the sender to retry (Telegraf does); Proxmox drops the batch either way.
                await Error(context, 503, "buffer full");
                return;
            }
        }
        context.Response.StatusCode = 204;
    }

    /// <summary>
    /// <c>Authorization: Token &lt;t&gt;</c> (v2), plus what HEC accepts (Bearer, Basic with the token as password),
    /// and the v1 <c>?p=</c> password.
    /// </summary>
    private static string? Token(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        if (header.StartsWith("Token ", StringComparison.OrdinalIgnoreCase))
        {
            return header[6..].Trim();
        }
        var password = request.Query["p"].ToString();
        return password.Length > 0 ? password : HecInput.Token(request);
    }

    private bool IsValid(string? token)
    {
        if (token is null)
        {
            return false;
        }
        var bytes = Encoding.UTF8.GetBytes(token);
        var ok = false;
        foreach (var expected in _tokens)
        {
            ok |= bytes.Length == expected.Length && CryptographicOperations.FixedTimeEquals(bytes, expected);
        }
        return ok;
    }

    private static async Task Error(HttpContext context, int status, string message)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync($$"""{"code":"{{(status == 401 ? "unauthorized" : "invalid")}}","message":"{{message}}"}""", context.RequestAborted);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "InfluxDB line protocol: listening on {Scheme} port {Port}")]
    private static partial void LogListening(ILogger logger, string scheme, int port);
}

/// <summary>
/// Receives InfluxDB line protocol datagrams (Proxmox's UDP metric server, Telegraf's socket_writer). Datagrams from
/// one sender are collected for up to a second, then go into the disk buffer together.
/// </summary>
public sealed partial class InfluxUdpInput(InputConfig config, DiskBuffer buffer, ILogger logger)
{
    private const int MaxBatchBytes = 1024 * 1024;
    private static readonly TimeSpan BatchFor = TimeSpan.FromSeconds(1);

    public async Task RunAsync(CancellationToken ct)
    {
        using var socket = SyslogUdpInput.Bind(config, SocketType.Dgram, ProtocolType.Udp);
        socket.ReceiveBufferSize = 4 * 1024 * 1024;
        LogListening(logger, config.Port);

        var data = new byte[65535];
        var batches = new Dictionary<string, (StringBuilder Text, DateTimeOffset Started)>(StringComparer.Ordinal);
        EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(batches.Count > 0 ? BatchFor : Timeout.InfiniteTimeSpan);
            try
            {
                received = await socket.ReceiveFromAsync(data, SocketFlags.None, any, wait.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                Flush(batches, all: true);
                continue;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                continue;
            }

            var from = (received.RemoteEndPoint as IPEndPoint)?.Address;
            var source = from is null ? string.Empty : (from.IsIPv4MappedToIPv6 ? from.MapToIPv4() : from).ToString();
            if (!batches.TryGetValue(source, out var batch))
            {
                batch = (new StringBuilder(), DateTimeOffset.UtcNow);
                batches[source] = batch;
            }
            batch.Text.Append(Encoding.UTF8.GetString(data, 0, received.ReceivedBytes).TrimEnd('\0')).Append('\n');
            if (batch.Text.Length > MaxBatchBytes)
            {
                Emit(source, batch.Text);
                batches.Remove(source);
            }
            Flush(batches, all: false);
        }
        Flush(batches, all: true);
    }

    private void Flush(Dictionary<string, (StringBuilder Text, DateTimeOffset Started)> batches, bool all)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (source, batch) in batches.ToList())
        {
            if (all || now - batch.Started >= BatchFor)
            {
                Emit(source, batch.Text);
                batches.Remove(source);
            }
        }
    }

    private void Emit(string source, StringBuilder text)
    {
        if (!buffer.TryEnqueue(MetricPush.Envelope(config.Job, source.Length > 0 ? source : null, "auto", text.ToString())))
        {
            LogDropped(logger, source);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "InfluxDB line protocol: listening on udp port {Port}")]
    private static partial void LogListening(ILogger logger, int port);

    [LoggerMessage(Level = LogLevel.Warning, Message = "InfluxDB line protocol: buffer full, dropped metrics from {Source}")]
    private static partial void LogDropped(ILogger logger, string source);
}
