using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
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
/// Receives OpenTelemetry (OTLP) logs and metrics as an OpenTelemetry Collector would, so SDKs, the Collector and
/// other OTLP exporters can send straight to the agent.
/// <list type="bullet">
/// <item>HTTP (<see cref="InputType.Otlp"/>, port 4318): <c>POST /v1/logs</c> and <c>/v1/metrics</c>, protobuf or JSON,
/// gzip allowed.</item>
/// <item>gRPC (<see cref="InputType.OtlpGrpc"/>, port 4317): the LogsService and MetricsService <c>Export</c> calls over
/// HTTP/2. The gRPC framing is a 5-byte prefix, so it's handled here without a gRPC library (the agent is AOT).</item>
/// </list>
/// Traces are accepted and discarded, so senders configured for all three signals don't log errors. Request bodies
/// go into the disk buffer as they are; the server decodes them (<see cref="OtlpPush"/>).
/// </summary>
public sealed partial class OtlpInput(InputConfig config, DiskBuffer buffer, X509Certificate2? tlsCertificate, ILogger logger, bool grpc)
{
    public const long MaxBodyBytes = 16 * 1024 * 1024;

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
            kestrel.Limits.MaxRequestBodySize = MaxBodyBytes;
            void Configure(ListenOptions listen)
            {
                // gRPC needs HTTP/2; without TLS that's HTTP/2 only ("prior knowledge"), as gRPC clients do.
                listen.Protocols = grpc ? HttpProtocols.Http2 : HttpProtocols.Http1AndHttp2;
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
        app.Run(grpc ? HandleGrpcAsync : HandleHttpAsync);
        await app.StartAsync(ct);
        LogListening(logger, grpc ? "gRPC" : "HTTP", config.Tls ? "with TLS" : "without TLS", config.Port);
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

    // ---- HTTP ---------------------------------------------------------------------------------------------------

    internal async Task HandleHttpAsync(HttpContext context)
    {
        var signal = (context.Request.Path.Value ?? string.Empty).TrimEnd('/') switch
        {
            "/v1/logs" => "logs",
            "/v1/metrics" => "metrics",
            "/v1/traces" => "traces",
            _ => null,
        };
        if (signal is null)
        {
            context.Response.StatusCode = 404;
            return;
        }
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            context.Response.StatusCode = 405;
            return;
        }
        var json = context.Request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true;
        if (!json && context.Request.ContentType?.StartsWith("application/x-protobuf", StringComparison.OrdinalIgnoreCase) != true)
        {
            await Reply(context, 415, json, "Content-Type must be application/x-protobuf or application/json");
            return;
        }
        if (_tokens.Length > 0 && !IsValid(HecInput.Token(context.Request)))
        {
            await Reply(context, 401, json, "unauthorized: send Authorization: Bearer <token>");
            return;
        }
        byte[] body;
        try
        {
            body = await HecInput.ReadBodyAsync(context.Request, context.RequestAborted);
        }
        catch (Exception ex) when (ex is Microsoft.AspNetCore.Http.BadHttpRequestException or InvalidDataException or IOException)
        {
            await Reply(context, 400, json, "invalid or too large body");
            return;
        }
        if (signal != "traces" && body.Length > 0 && !Accept(context, signal, json, body))
        {
            // OTLP/HTTP: 503 is retryable.
            await Reply(context, 503, json, "buffer full");
            return;
        }
        // An empty Export*ServiceResponse: no partial success to report.
        context.Response.StatusCode = 200;
        context.Response.ContentType = json ? "application/json" : "application/x-protobuf";
        if (json)
        {
            await context.Response.WriteAsync("{}", context.RequestAborted);
        }
    }

    private static async Task Reply(HttpContext context, int status, bool json, string message)
    {
        context.Response.StatusCode = status;
        if (json)
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync($$"""{"code":{{status}},"message":"{{message}}"}""", context.RequestAborted);
        }
        else
        {
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync(message, context.RequestAborted);
        }
    }

    // ---- gRPC ---------------------------------------------------------------------------------------------------

    internal async Task HandleGrpcAsync(HttpContext context)
    {
        var signal = context.Request.Path.Value switch
        {
            "/opentelemetry.proto.collector.logs.v1.LogsService/Export" => "logs",
            "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export" => "metrics",
            "/opentelemetry.proto.collector.trace.v1.TraceService/Export" => "traces",
            _ => null,
        };
        if (signal is null)
        {
            GrpcStatus(context, 12, "unknown method"); // UNIMPLEMENTED
            return;
        }
        if (_tokens.Length > 0 && !IsValid(HecInput.Token(context.Request)))
        {
            GrpcStatus(context, 16, "send authorization: Bearer <token>"); // UNAUTHENTICATED
            return;
        }
        byte[] message;
        try
        {
            message = await ReadGrpcMessageAsync(context.Request, context.RequestAborted);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or Microsoft.AspNetCore.Http.BadHttpRequestException)
        {
            GrpcStatus(context, 3, ex.Message); // INVALID_ARGUMENT
            return;
        }
        if (signal != "traces" && message.Length > 0 && !Accept(context, signal, json: false, message))
        {
            GrpcStatus(context, 14, "buffer full"); // UNAVAILABLE: retryable
            return;
        }
        // An empty response message, then grpc-status 0 in the trailers.
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/grpc";
        await context.Response.Body.WriteAsync(new byte[5], context.RequestAborted);
        if (context.Response.SupportsTrailers())
        {
            context.Response.AppendTrailer("grpc-status", "0");
        }
        else
        {
            context.Response.Headers["grpc-status"] = "0";
        }
    }

    /// <summary>A "trailers-only" gRPC response: the status goes in the headers.</summary>
    private static void GrpcStatus(HttpContext context, int status, string message)
    {
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/grpc";
        context.Response.Headers["grpc-status"] = status.ToString(System.Globalization.CultureInfo.InvariantCulture);
        context.Response.Headers["grpc-message"] = Uri.EscapeDataString(message);
    }

    /// <summary>One length-prefixed gRPC message: a compressed flag byte, a 4-byte big-endian length, the message.</summary>
    internal static async Task<byte[]> ReadGrpcMessageAsync(HttpRequest request, CancellationToken ct)
    {
        var prefix = new byte[5];
        await request.Body.ReadExactlyAsync(prefix, ct);
        var length = BinaryPrimitives.ReadUInt32BigEndian(prefix.AsSpan(1));
        if (length > MaxBodyBytes)
        {
            throw new InvalidDataException("message too large");
        }
        var message = new byte[length];
        await request.Body.ReadExactlyAsync(message, ct);
        if (prefix[0] == 0)
        {
            return message;
        }
        var encoding = request.Headers["grpc-encoding"].ToString();
        if (!encoding.Equals("gzip", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"unsupported grpc-encoding \"{encoding}\"; use gzip or none");
        }
        await using var gzip = new GZipStream(new MemoryStream(message), CompressionMode.Decompress);
        using var output = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await gzip.ReadAsync(chunk, ct)) > 0)
        {
            if (output.Length + read > MaxBodyBytes)
            {
                throw new InvalidDataException("message too large");
            }
            output.Write(chunk, 0, read);
        }
        return output.ToArray();
    }

    // ---- Both -----------------------------------------------------------------------------------------------------

    private bool Accept(HttpContext context, string signal, bool json, byte[] body)
    {
        var from = context.Connection.RemoteIpAddress;
        var source = from is null ? null : (from.IsIPv4MappedToIPv6 ? from.MapToIPv4() : from).ToString();
        var envelope = OtlpPush.Envelope(config.Job, source, signal, json, body);
        return Emit?.Invoke(envelope) ?? buffer.TryEnqueue(envelope);
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

    [LoggerMessage(Level = LogLevel.Information, Message = "OpenTelemetry (OTLP/{Protocol}): listening {Tls} on port {Port}")]
    private static partial void LogListening(ILogger logger, string protocol, string tls, int port);
}
