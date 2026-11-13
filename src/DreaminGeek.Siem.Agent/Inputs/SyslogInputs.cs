using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>UDP syslog: one message per datagram.</summary>
public sealed partial class SyslogUdpInput(InputConfig config, SourceHints hints, DiskBuffer buffer, ILogger logger)
{
    public async Task RunAsync(CancellationToken ct)
    {
        using var socket = Bind(config, SocketType.Dgram, ProtocolType.Udp);
        socket.ReceiveBufferSize = 4 * 1024 * 1024; // absorb bursts; the kernel may cap this (net.core.rmem_max)
        LogListening(logger, "udp", config.Port);

        var data = new byte[65535];
        EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(data, SocketFlags.None, any, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                continue;
            }

            var message = Encoding.UTF8.GetString(data, 0, received.ReceivedBytes).TrimEnd('\r', '\n', '\0', ' ');
            if (message.Length == 0)
            {
                continue;
            }
            var from = (received.RemoteEndPoint as IPEndPoint)?.Address;
            buffer.TryEnqueue(Envelope("syslog-udp", from, message, hints.Resolve(from, config.Dataset)));
        }
    }

    /// <summary>
    /// Binds a socket. "Any" (<c>0.0.0.0</c>, <c>::</c>, <c>*</c>) means dual-stack IPv6 when the host
    /// supports it, otherwise plain IPv4 (common in LXCs with IPv6 disabled).
    /// </summary>
    internal static Socket Bind(InputConfig config, SocketType type, ProtocolType protocol)
    {
        if (config.BindAddress is "0.0.0.0" or "" or "*" or "::")
        {
            if (Socket.OSSupportsIPv6)
            {
                Socket? v6 = null;
                try
                {
                    v6 = new Socket(AddressFamily.InterNetworkV6, type, protocol) { DualMode = true };
                    v6.Bind(new IPEndPoint(IPAddress.IPv6Any, config.Port));
                    return v6;
                }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressFamilyNotSupported or SocketError.AddressNotAvailable or SocketError.ProtocolNotSupported)
                {
                    v6?.Dispose();
                }
            }
            return BindTo(IPAddress.Any, config.Port, type, protocol);
        }
        return BindTo(IPAddress.Parse(config.BindAddress), config.Port, type, protocol);
    }

    private static Socket BindTo(IPAddress address, int port, SocketType type, ProtocolType protocol)
    {
        var socket = new Socket(address.AddressFamily, type, protocol);
        try
        {
            socket.Bind(new IPEndPoint(address, port));
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    internal static RawEnvelope Envelope(string input, IPAddress? from, string message, string? dataset) =>
        new(DateTimeOffset.UtcNow, input, from is null ? null : (from.IsIPv4MappedToIPv6 ? from.MapToIPv4() : from).ToString(), message, dataset);

    [LoggerMessage(Level = LogLevel.Information, Message = "Listening for syslog on {Protocol}/{Port}")]
    internal static partial void LogListening(ILogger logger, string protocol, int port);
}

/// <summary>TCP syslog (RFC 6587 framing), optionally wrapped in TLS (RFC 5425) using the agent's certificate.</summary>
public sealed partial class SyslogTcpInput(InputConfig config, SourceHints hints, DiskBuffer buffer, X509Certificate2? tlsCertificate, ILogger logger)
{
    private const int MaxConnections = 512;
    private int _connections;

    public async Task RunAsync(CancellationToken ct)
    {
        var protocol = tlsCertificate is null ? "tcp" : "tls";
        using var listener = SyslogUdpInput.Bind(config, SocketType.Stream, ProtocolType.Tcp);
        listener.Listen(backlog: 128);
        SyslogUdpInput.LogListening(logger, protocol, config.Port);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = new TcpClient { Client = await listener.AcceptAsync(ct) };
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (Interlocked.Increment(ref _connections) > MaxConnections)
                {
                    Interlocked.Decrement(ref _connections);
                    client.Dispose();
                    continue;
                }
                _ = HandleAsync(client, protocol, ct);
            }
        }
        finally
        {
            listener.Close();
        }
    }

    private async Task HandleAsync(TcpClient client, string protocol, CancellationToken ct)
    {
        var from = (client.Client.RemoteEndPoint as IPEndPoint)?.Address;
        var dataset = hints.Resolve(from, config.Dataset);
        var input = "syslog-" + protocol;
        try
        {
            using (client)
            {
                Stream stream = client.GetStream();
                if (tlsCertificate is not null)
                {
                    var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                    using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    handshake.CancelAfter(TimeSpan.FromSeconds(10));
                    await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = tlsCertificate }, handshake.Token);
                    stream = ssl;
                }

                await using (stream)
                {
                    var decoder = new SyslogFrameDecoder();
                    var data = new byte[16 * 1024];
                    int read;
                    while ((read = await stream.ReadAsync(data, ct)) > 0)
                    {
                        foreach (var message in decoder.Feed(data.AsSpan(0, read)))
                        {
                            buffer.TryEnqueue(SyslogUdpInput.Envelope(input, from, message, dataset));
                        }
                    }
                    if (decoder.Flush() is { } last)
                    {
                        buffer.TryEnqueue(SyslogUdpInput.Envelope(input, from, last, dataset));
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or System.Security.Authentication.AuthenticationException or OperationCanceledException)
        {
            if (!ct.IsCancellationRequested)
            {
                LogConnectionError(logger, protocol, from, ex.Message);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _connections);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Syslog {Protocol} connection from {Remote} ended: {Error}")]
    private static partial void LogConnectionError(ILogger logger, string protocol, IPAddress? remote, string error);
}
