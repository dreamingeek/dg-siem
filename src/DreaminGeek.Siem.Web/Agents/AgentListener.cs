using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace DreaminGeek.Siem.Web.Agents;

/// <summary>
/// TLS for the agent port. The server presents its CA-issued certificate and asks for a client
/// certificate. (New agents get the CA from <c>GET /api/v1/agents/ca</c> and verify it against the
/// fingerprint in their token; .NET on Linux does not send a self-signed root in the TLS chain.) A missing client certificate is allowed at the TLS layer (enrollment has
/// none yet); one that does not chain to our CA is rejected. Certificate authentication then maps
/// it to a live, non-revoked agent.
/// </summary>
public static class AgentListener
{
    public static void UseAgentTls(this ListenOptions listen, CertificateAuthority ca)
    {
        ArgumentNullException.ThrowIfNull(listen);
        ArgumentNullException.ThrowIfNull(ca);

        SslStreamCertificateContext? context = null;
        X509Certificate2? contextCert = null;
        var gate = new Lock();

        listen.UseHttps(new TlsHandshakeCallbackOptions
        {
            HandshakeTimeout = TimeSpan.FromSeconds(10),
            OnConnection = _ =>
            {
                lock (gate)
                {
                    var current = ca.ServerCertificate; // re-issued automatically near expiry
                    if (!ReferenceEquals(current, contextCert))
                    {
                        context = SslStreamCertificateContext.Create(current, additionalCertificates: null, offline: true);
                        contextCert = current;
                    }
                }

                return ValueTask.FromResult(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = context,
                    ClientCertificateRequired = true,
                    // No certificate (enrollment) is allowed; a certificate that is present must be ours.
                    RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                        certificate is null || ca.IsIssuedByUs(certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData())),
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                });
            },
        });
    }
}
