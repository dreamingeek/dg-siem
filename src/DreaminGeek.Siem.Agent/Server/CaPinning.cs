using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DreaminGeek.Siem.Agent.Server;

/// <summary>Server certificate checks: the agent trusts only the DG SIEM CA, never the OS trust store.</summary>
public static class CaPinning
{
    /// <summary>After enrollment: the server certificate must chain to the stored CA and match the hostname.</summary>
    public static bool Validate(X509Certificate2 ca, X509Certificate? certificate, SslPolicyErrors errors)
    {
        if (certificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) || errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            return false;
        }
        var leaf = AsCert2(certificate);
        return !IsAgentCertificate(leaf) && ChainsTo(ca, leaf);
    }

    /// <summary>
    /// True for a certificate the CA issued to an agent. Those chain to the same CA and carry serverAuth
    /// (for the TLS syslog input), so without this check an enrolled agent could pose as the server.
    /// The server's own certificate has serverAuth only, no OU and no agent URI.
    /// </summary>
    public static bool IsAgentCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var usage in eku.EnhancedKeyUsages)
                {
                    if (usage.Value == ClientAuthOid)
                    {
                        return true;
                    }
                }
            }
            else if (extension.Oid?.Value == SubjectAltNameOid
                && System.Text.Encoding.ASCII.GetString(extension.RawData).Contains(AgentUriPrefix, StringComparison.Ordinal))
            {
                return true;
            }
        }
        foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (rdn.GetSingleElementType().Value == OrganizationalUnitOid
                && string.Equals(rdn.GetSingleElementValue(), AgentOrganizationalUnit, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string OrganizationalUnitOid = "2.5.4.11";
    private const string AgentUriPrefix = "urn:dg-siem:agent:";
    private const string AgentOrganizationalUnit = "dg-siem-agent";

    /// <summary>True if <paramref name="ca"/> is the CA whose SHA-256 the enrollment token pins.</summary>
    public static bool MatchesPin(X509Certificate2 ca, string caFingerprintHex)
    {
        ArgumentNullException.ThrowIfNull(ca);
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(Convert.ToHexStringLower(ca.GetCertHash(HashAlgorithmName.SHA256))),
            System.Text.Encoding.ASCII.GetBytes(caFingerprintHex.ToLowerInvariant()));
    }

    private static bool ChainsTo(X509Certificate2 ca, X509Certificate2 leaf)
    {
        using var verify = new X509Chain();
        verify.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        verify.ChainPolicy.CustomTrustStore.Add(ca);
        verify.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        verify.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // serverAuth
        return verify.Build(leaf);
    }

    private static X509Certificate2 AsCert2(X509Certificate certificate) =>
        certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
}
