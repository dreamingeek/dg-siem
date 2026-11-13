using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DreaminGeek.Siem.Agent.Server;

/// <summary>Generates the agent key and CSR. The private key never leaves the machine.</summary>
public static class KeyMaterial
{
    public static (string KeyPem, string CsrPem) NewKeyAndCsr(string agentName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(agentName);
        var request = new CertificateRequest(subject.Build(), key, HashAlgorithmName.SHA256);
        return (key.ExportPkcs8PrivateKeyPem(), request.CreateSigningRequestPem());
    }
}
