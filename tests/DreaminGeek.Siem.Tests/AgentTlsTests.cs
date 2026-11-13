using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DreaminGeek.Siem.Agent.Server;

namespace DreaminGeek.Siem.Tests;

/// <summary>
/// The agent's certificate comes from PEM files. On Windows, SChannel can't use a PEM-loaded (ephemeral) key, so
/// this does a real mutual-TLS handshake with it. Runs everywhere; the Windows CI job is the one that matters.
/// </summary>
[Trait("Category", "Windows")]
public sealed class AgentTlsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("dgsiem-tls-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public async Task Client_certificate_from_pem_works_for_mutual_tls()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        // The agent's key and certificate, written as the agent stores them.
        using (var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var request = new CertificateRequest("CN=win-agent", agentKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));
            using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-5), ca.NotAfter.AddHours(-1), [1, 2, 3, 4]);
            File.WriteAllText(Path.Combine(_dir, "agent.crt.pem"), issued.ExportCertificatePem());
            File.WriteAllText(Path.Combine(_dir, "agent.key.pem"), agentKey.ExportPkcs8PrivateKeyPem());
        }
        using var clientCert = new AgentStore(_dir).LoadClientCertificate();

        // A server that requires a client certificate, as the agent port does.
        using var serverCert = ServerCertificate(ca);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        X509Certificate? seenByServer = null;
        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync();
            await using var ssl = new SslStream(accepted.GetStream(), false, (_, cert, _, _) => cert is not null);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCert,
                ClientCertificateRequired = true,
            });
            seenByServer = ssl.RemoteCertificate;
            await ssl.WriteAsync(new byte[] { 42 });
        });

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await using var client = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await client.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            ClientCertificates = [clientCert],
        });
        var buffer = new byte[1];
        Assert.Equal(1, await client.ReadAsync(buffer));
        await serverTask;

        Assert.NotNull(seenByServer);
        Assert.Equal("CN=win-agent", seenByServer!.Subject);
    }

    private static X509Certificate2 ServerCertificate(X509Certificate2 ca)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-5), ca.NotAfter.AddHours(-1), [5, 6, 7, 8]);
        return AgentStore.UsableForTls(issued.CopyWithPrivateKey(key));
    }
}
