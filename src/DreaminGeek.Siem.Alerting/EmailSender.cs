using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace DreaminGeek.Siem.Alerting;

/// <summary>Sending failed; the message is shown to the admin as-is.</summary>
public sealed class EmailException(string message, Exception? inner = null) : Exception(message, inner);

public interface IEmailSender
{
    Task SendAsync(SmtpSettings settings, IReadOnlyList<string> recipients, string subject, string html, string text, CancellationToken ct);
}

/// <summary>Sends through the configured SMTP relay with MailKit.</summary>
public sealed class SmtpEmailSender : IEmailSender
{
    public async Task SendAsync(SmtpSettings settings, IReadOnlyList<string> recipients, string subject, string html, string text, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(recipients);
        if (!settings.IsConfigured)
        {
            throw new EmailException("Email isn't set up. Add the SMTP relay under Administration → Notifications.");
        }

        var message = new MimeMessage();
        try
        {
            message.From.Add(new MailboxAddress(settings.FromName ?? string.Empty, settings.FromAddress));
            foreach (var address in recipients)
            {
                message.To.Add(MailboxAddress.Parse(address));
            }
        }
        catch (ParseException ex)
        {
            throw new EmailException($"Bad email address: {ex.Message}", ex);
        }
        message.Subject = subject;
        message.Body = new BodyBuilder { HtmlBody = html, TextBody = text }.ToMessageBody();

        var security = settings.Security switch
        {
            SmtpSecurity.None => SecureSocketOptions.None,
            SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
            SmtpSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect,
            _ => SecureSocketOptions.Auto,
        };

        using var client = new SmtpClient { Timeout = 30_000 };
        try
        {
            await client.ConnectAsync(settings.Host, settings.Port, security, ct);
            if (!string.IsNullOrEmpty(settings.Username))
            {
                await client.AuthenticateAsync(settings.Username, settings.Password ?? string.Empty, ct);
            }
            await client.SendAsync(message, ct);
            await client.DisconnectAsync(true, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is SmtpCommandException or SmtpProtocolException
            or AuthenticationException or SslHandshakeException or System.Net.Sockets.SocketException or IOException or TimeoutException)
        {
            throw new EmailException($"Sending through {settings.Host}:{settings.Port} failed: {ex.Message}", ex);
        }
    }
}
