using System.Net;
using System.Net.Sockets;
using System.Text;
using DreaminGeek.Siem.Alerting;

namespace DreaminGeek.Siem.Tests;

/// <summary>
/// The SMTP sender against a small in-process SMTP server, so a MailKit upgrade that changes how sending works
/// shows up here rather than in an admin's inbox.
/// </summary>
public sealed class EmailSenderTests
{
    /// <summary>Just enough SMTP: EHLO, MAIL, RCPT (refusing nobody@), DATA, QUIT. Records what it was sent.</summary>
    private sealed class FakeSmtp : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly Task _serve;
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public List<string> Recipients { get; } = [];
        public string Data { get; private set; } = string.Empty;

        public FakeSmtp()
        {
            _listener.Start();
            _serve = ServeAsync();
        }

        private async Task ServeAsync()
        {
            using var client = await _listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            await using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
            await writer.WriteLineAsync("220 fake.example.com ESMTP");
            while (await reader.ReadLineAsync() is { } line)
            {
                var verb = line.Split(' ', ':')[0].ToUpperInvariant();
                switch (verb)
                {
                    case "EHLO":
                        await writer.WriteLineAsync("250-fake.example.com");
                        await writer.WriteLineAsync("250 8BITMIME");
                        break;
                    case "MAIL":
                        await writer.WriteLineAsync("250 OK");
                        break;
                    case "RCPT":
                        if (line.Contains("nobody@", StringComparison.OrdinalIgnoreCase))
                        {
                            await writer.WriteLineAsync("550 5.1.1 No such user");
                        }
                        else
                        {
                            Recipients.Add(line[(line.IndexOf('<', StringComparison.Ordinal) + 1)..line.IndexOf('>', StringComparison.Ordinal)]);
                            await writer.WriteLineAsync("250 OK");
                        }
                        break;
                    case "DATA":
                        await writer.WriteLineAsync("354 Go ahead");
                        var data = new StringBuilder();
                        while (await reader.ReadLineAsync() is { } d && d != ".")
                        {
                            data.AppendLine(d);
                        }
                        Data = data.ToString();
                        await writer.WriteLineAsync("250 Queued");
                        break;
                    case "RSET" or "NOOP":
                        await writer.WriteLineAsync("250 OK");
                        break;
                    case "QUIT":
                        await writer.WriteLineAsync("221 Bye");
                        return;
                    default:
                        await writer.WriteLineAsync("502 Not implemented");
                        break;
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            await Task.WhenAny(_serve, Task.Delay(2000));
        }
    }

    private static SmtpSettings Settings(int port) =>
        new("127.0.0.1", port, SmtpSecurity.None, Username: null, Password: null, FromAddress: "siem@example.com", FromName: "DG SIEM");

    [Fact]
    public async Task Sends_a_message_with_html_and_text()
    {
        await using var smtp = new FakeSmtp();
        await new SmtpEmailSender().SendAsync(Settings(smtp.Port), ["ops@example.com", "chris@example.com"],
            "Alert: storage almost full", "<p>Storage is <b>93%</b> full.</p>", "Storage is 93% full.", CancellationToken.None);

        Assert.Equal(["ops@example.com", "chris@example.com"], smtp.Recipients);
        Assert.Contains("Subject: Alert: storage almost full", smtp.Data, StringComparison.Ordinal);
        Assert.Contains("From: DG SIEM <siem@example.com>", smtp.Data, StringComparison.Ordinal);
        Assert.Contains("text/html", smtp.Data, StringComparison.Ordinal);
        Assert.Contains("Storage is 93% full.", smtp.Data, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_recipient_is_reported()
    {
        await using var smtp = new FakeSmtp();
        var ex = await Assert.ThrowsAsync<EmailException>(() => new SmtpEmailSender().SendAsync(Settings(smtp.Port), ["nobody@example.com"],
            "Test", "<p>x</p>", "x", CancellationToken.None));
        Assert.Contains($"127.0.0.1:{smtp.Port} failed", ex.Message, StringComparison.Ordinal);
        Assert.Contains("No such user", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Bad_addresses_and_missing_setup_are_explained()
    {
        Assert.Contains("Bad email address", (await Assert.ThrowsAsync<EmailException>(() => new SmtpEmailSender().SendAsync(
            Settings(25), ["not an address"], "x", "x", "x", CancellationToken.None))).Message, StringComparison.Ordinal);
        Assert.Contains("isn't set up", (await Assert.ThrowsAsync<EmailException>(() => new SmtpEmailSender().SendAsync(
            new SmtpSettings("", 25, SmtpSecurity.None, null, null, "", null), ["ops@example.com"], "x", "x", "x", CancellationToken.None))).Message, StringComparison.Ordinal);
    }
}
