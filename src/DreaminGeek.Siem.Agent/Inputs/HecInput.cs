using System.Buffers;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>
/// Splunk-compatible HTTP Event Collector: <c>POST /services/collector/event</c> (JSON events),
/// <c>POST /services/collector/raw</c> (lines) and <c>GET /services/collector/health</c>, with
/// <c>Authorization: DGSIEM &lt;token&gt;</c>. Each event goes into the disk buffer as a compact JSON object
/// (input <c>hec</c>); the server unwraps it and parses the event like any other log line.
/// </summary>
public sealed partial class HecInput(InputConfig config, DiskBuffer buffer, X509Certificate2? tlsCertificate, ILogger logger)
{
    public const long MaxBodyBytes = 16 * 1024 * 1024;
    private const int MaxEventsPerRequest = 100_000;

    /// <summary>For tests: called instead of the buffer when set.</summary>
    internal Func<RawEnvelope, bool>? Emit { get; init; }

    private readonly byte[][] _tokens = (config.Tokens ?? []).Select(Encoding.UTF8.GetBytes).ToArray();

    public async Task RunAsync(CancellationToken ct)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ApplicationName = "dg-siem-agent" });
        builder.Logging.ClearProviders(); // the agent logs for itself
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = MaxBodyBytes;
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
        var kind = path switch
        {
            "/services/collector" or "/services/collector/event" or "/services/collector/event/1.0" => "event",
            "/services/collector/raw" or "/services/collector/raw/1.0" => "raw",
            "/services/collector/health" or "/services/collector/health/1.0" => "health",
            _ => null,
        };
        if (kind is null)
        {
            await Reply(context, 404, "The requested URL was not found on this server.", 404);
            return;
        }
        if (kind == "health")
        {
            await Reply(context, 200, "HEC is healthy", 17);
            return;
        }
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await Reply(context, 405, "Use POST", 405);
            return;
        }
        var token = Token(context.Request);
        if (token is null)
        {
            await Reply(context, 401, "Token is required", 2);
            return;
        }
        if (!IsValid(token))
        {
            await Reply(context, 403, "Invalid token", 4);
            return;
        }

        byte[] body;
        try
        {
            body = await ReadBodyAsync(context.Request, context.RequestAborted);
        }
        catch (Exception ex) when (ex is Microsoft.AspNetCore.Http.BadHttpRequestException or InvalidDataException or IOException)
        {
            await Reply(context, 400, "Invalid data format", 6);
            return;
        }
        if (body.Length == 0)
        {
            await Reply(context, 400, "No data", 5);
            return;
        }

        var query = context.Request.Query;
        var result = kind == "raw"
            ? HecPayload.FromRaw(body, query["host"], query["source"], query["sourcetype"])
            : HecPayload.FromEvents(body);
        if (result.Error is { } error)
        {
            await Reply(context, 400, error.Text, error.Code, result.InvalidIndex);
            return;
        }

        var from = context.Connection.RemoteIpAddress;
        var source = from is null ? null : (from.IsIPv4MappedToIPv6 ? from.MapToIPv4() : from).ToString();
        var now = DateTimeOffset.UtcNow;
        foreach (var message in result.Events)
        {
            var envelope = new RawEnvelope(now, "hec", source, message, config.Dataset);
            if (!(Emit?.Invoke(envelope) ?? buffer.TryEnqueue(envelope)))
            {
                await Reply(context, 503, "Server is busy", 9);
                return;
            }
        }
        await Reply(context, 200, "Success", 0);
    }

    /// <summary>
    /// <c>Authorization: DGSIEM &lt;t&gt;</c> or <c>Bearer &lt;t&gt;</c>, Basic with the token as password, or <c>?token=</c>.
    /// The <c>Splunk</c> scheme is accepted too, because existing HEC clients (Docker's log driver, Vector, Fluent Bit) hardcode it.
    /// </summary>
    private static string? Token(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        foreach (var scheme in (string[])["DGSIEM ", "Bearer ", "Splunk "])
        {
            if (header.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            {
                return header[scheme.Length..].Trim();
            }
        }
        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
                var colon = decoded.IndexOf(':', StringComparison.Ordinal);
                return colon >= 0 ? decoded[(colon + 1)..] : decoded;
            }
            catch (FormatException)
            {
                return null;
            }
        }
        var query = request.Query["token"].ToString();
        return query.Length > 0 ? query : null;
    }

    private bool IsValid(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var ok = false;
        foreach (var expected in _tokens)
        {
            ok |= bytes.Length == expected.Length && CryptographicOperations.FixedTimeEquals(bytes, expected);
        }
        return ok;
    }

    private static async Task<byte[]> ReadBodyAsync(HttpRequest request, CancellationToken ct)
    {
        Stream stream = request.Body;
        if (string.Equals(request.Headers.ContentEncoding, "gzip", StringComparison.OrdinalIgnoreCase))
        {
            stream = new GZipStream(stream, CompressionMode.Decompress);
        }
        await using (stream)
        {
            using var memory = new MemoryStream();
            var chunk = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                int read;
                while ((read = await stream.ReadAsync(chunk, ct)) > 0)
                {
                    if (memory.Length + read > MaxBodyBytes)
                    {
                        throw new InvalidDataException("Body too large");
                    }
                    memory.Write(chunk, 0, read);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(chunk);
            }
            return memory.ToArray();
        }
    }

    private static async Task Reply(HttpContext context, int status, string text, int code, int? invalidEventNumber = null)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        using var json = new MemoryStream();
        using (var writer = new Utf8JsonWriter(json))
        {
            writer.WriteStartObject();
            writer.WriteString("text", text);
            writer.WriteNumber("code", code);
            if (invalidEventNumber is { } n)
            {
                writer.WriteNumber("invalid-event-number", n);
            }
            writer.WriteEndObject();
        }
        await context.Response.Body.WriteAsync(json.ToArray());
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Listening for HEC on {Scheme}/{Port}")]
    private static partial void LogListening(ILogger logger, string scheme, int port);
}

/// <summary>Turns HEC request bodies into one compact JSON object per event. Pure, for tests.</summary>
public static class HecPayload
{
    public sealed record Problem(string Text, int Code);

    public sealed record Result(IReadOnlyList<string> Events, Problem? Error = null, int? InvalidIndex = null);

    private static readonly Problem InvalidFormat = new("Invalid data format", 6);
    private static readonly Problem EventRequired = new("Event field is required", 12);
    private static readonly Problem EventBlank = new("Event field cannot be blank", 13);

    /// <summary>One or more JSON objects back to back (Splunk's format; a JSON array is accepted too).</summary>
    public static Result FromEvents(ReadOnlySpan<byte> body)
    {
        var events = new List<string>();
        var reader = new Utf8JsonReader(body, new JsonReaderOptions { AllowMultipleValues = true, CommentHandling = JsonCommentHandling.Skip });
        try
        {
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.StartArray && reader.CurrentDepth == 0)
                {
                    continue; // [ {...}, {...} ]
                }
                if (reader.TokenType == JsonTokenType.EndArray && reader.CurrentDepth == 0)
                {
                    continue;
                }
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    return new Result([], InvalidFormat, events.Count);
                }
                using var doc = JsonDocument.ParseValue(ref reader);
                var root = doc.RootElement;
                if (!root.TryGetProperty("event", out var evt))
                {
                    return new Result([], EventRequired, events.Count);
                }
                if (evt.ValueKind == JsonValueKind.Null || (evt.ValueKind == JsonValueKind.String && evt.GetString()!.Length == 0))
                {
                    return new Result([], EventBlank, events.Count);
                }
                events.Add(Compact(root));
                if (events.Count > 100_000)
                {
                    return new Result([], new Problem("Too many events in one request", 6), events.Count);
                }
            }
        }
        catch (JsonException)
        {
            return new Result([], InvalidFormat, events.Count);
        }
        return events.Count == 0 ? new Result([], new Problem("No data", 5)) : new Result(events);
    }

    /// <summary>Each non-blank line is an event; the query string can name host, source and sourcetype.</summary>
    public static Result FromRaw(ReadOnlySpan<byte> body, string? host, string? source, string? sourcetype)
    {
        var events = new List<string>();
        foreach (var raw in Encoding.UTF8.GetString(body).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0)
            {
                continue;
            }
            using var json = new MemoryStream();
            using (var writer = new Utf8JsonWriter(json))
            {
                writer.WriteStartObject();
                writer.WriteString("event", line);
                if (!string.IsNullOrEmpty(host))
                {
                    writer.WriteString("host", host);
                }
                if (!string.IsNullOrEmpty(source))
                {
                    writer.WriteString("source", source);
                }
                if (!string.IsNullOrEmpty(sourcetype))
                {
                    writer.WriteString("sourcetype", sourcetype);
                }
                writer.WriteEndObject();
            }
            events.Add(Encoding.UTF8.GetString(json.ToArray()));
        }
        return events.Count == 0 ? new Result([], new Problem("No data", 5)) : new Result(events);
    }

    /// <summary>The object re-written on one line (events are stored one per line).</summary>
    private static string Compact(JsonElement element)
    {
        using var json = new MemoryStream();
        using (var writer = new Utf8JsonWriter(json))
        {
            element.WriteTo(writer);
        }
        return Encoding.UTF8.GetString(json.ToArray());
    }
}
