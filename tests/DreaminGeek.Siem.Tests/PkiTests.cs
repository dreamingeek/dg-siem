using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DreaminGeek.Siem.Agent.Server;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Web.Agents;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Tests;

public sealed class PkiTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "dgsiem-pki-" + Guid.NewGuid().ToString("N"));
    private readonly CertificateAuthority _ca;

    public PkiTests()
    {
        _ca = new CertificateAuthority(
            Options.Create(new PkiOptions { Directory = _dir, AgentHostnames = ["siem-agents.example.com", "10.0.0.5"] }),
            NullLogger<CertificateAuthority>.Instance);
    }

    [Fact]
    public void Issues_agent_certificates_that_chain_to_the_ca()
    {
        var (_, csr) = KeyMaterial.NewKeyAndCsr("acme-log-col");
        var id = Guid.NewGuid();
        using var cert = _ca.IssueAgentCertificate(csr, id, "acme-log-col", "acme");

        Assert.True(_ca.IsIssuedByUs(cert));
        Assert.Contains("CN=acme-log-col", cert.Subject, StringComparison.Ordinal);
        Assert.Contains("O=acme", cert.Subject, StringComparison.Ordinal);
        Assert.Contains($"urn:dg-siem:agent:{id:D}", cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false), StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_certificates_from_another_ca()
    {
        using var otherDir = new TempCa();
        var (_, csr) = KeyMaterial.NewKeyAndCsr("rogue");
        using var foreign = otherDir.Ca.IssueAgentCertificate(csr, Guid.NewGuid(), "rogue", "acme");
        Assert.False(_ca.IsIssuedByUs(foreign));
    }

    [Fact]
    public void Rejects_a_tampered_csr()
    {
        var (_, csr) = KeyMaterial.NewKeyAndCsr("acme-log-col");
        var tampered = csr.Replace(csr.Split('\n')[3], csr.Split('\n')[3][..^4] + "AAAA", StringComparison.Ordinal);
        Assert.ThrowsAny<CryptographicException>(() => _ca.IssueAgentCertificate(tampered, Guid.NewGuid(), "x", "acme"));
    }

    [Fact]
    public void Ca_and_server_cert_persist_across_restarts()
    {
        var fingerprint = _ca.CaFingerprint;
        var serverThumb = CertificateAuthority.Thumbprint(_ca.ServerCertificate);
        using var reloaded = new CertificateAuthority(
            Options.Create(new PkiOptions { Directory = _dir, AgentHostnames = ["siem-agents.example.com", "10.0.0.5"] }),
            NullLogger<CertificateAuthority>.Instance);
        Assert.Equal(fingerprint, reloaded.CaFingerprint);
        Assert.Equal(serverThumb, CertificateAuthority.Thumbprint(reloaded.ServerCertificate));
    }

    [Fact]
    public void Server_cert_is_reissued_when_hostnames_change()
    {
        var before = CertificateAuthority.Thumbprint(_ca.ServerCertificate);
        using var changed = new CertificateAuthority(
            Options.Create(new PkiOptions { Directory = _dir, AgentHostnames = ["new-name.example.com"] }),
            NullLogger<CertificateAuthority>.Instance);
        Assert.NotEqual(before, CertificateAuthority.Thumbprint(changed.ServerCertificate));
        Assert.Equal(_ca.CaFingerprint, changed.CaFingerprint);
    }

    [Fact]
    public void Agent_validates_server_cert_against_pinned_ca()
    {
        using var caPublic = X509CertificateLoader.LoadCertificate(_ca.CaCertificate.RawData);
        Assert.True(CaPinning.Validate(caPublic, _ca.ServerCertificate, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(CaPinning.Validate(caPublic, _ca.ServerCertificate, SslPolicyErrors.RemoteCertificateNameMismatch));

        using var other = new TempCa();
        Assert.False(CaPinning.Validate(caPublic, other.Ca.ServerCertificate, SslPolicyErrors.None));
    }

    [Fact]
    public void Agent_certificates_cannot_pose_as_the_server()
    {
        // An agent enrolled under the server's hostname gets a CA-signed cert with serverAuth (for its
        // TLS syslog input); other agents must still refuse it as the server's certificate.
        using var caPublic = X509CertificateLoader.LoadCertificate(_ca.CaCertificate.RawData);
        var (_, csr) = KeyMaterial.NewKeyAndCsr("siem-agents.example.com");
        using var impostor = _ca.IssueAgentCertificate(csr, Guid.NewGuid(), "siem-agents.example.com", "acme");
        Assert.True(CaPinning.IsAgentCertificate(impostor));
        Assert.False(CaPinning.Validate(caPublic, impostor, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(CaPinning.IsAgentCertificate(_ca.ServerCertificate));
    }

    [Fact]
    public void Agents_cannot_enroll_under_the_server_name()
    {
        Assert.True(_ca.IsServerName("SIEM-agents.example.com"));
        Assert.True(_ca.IsServerName("localhost"));
        Assert.False(_ca.IsServerName("acme-log-col"));
    }

    [Fact]
    public void Enrollment_tokens_round_trip_and_pin_the_ca()
    {
        var token = EnrollmentTokenFormat.Create(_ca.CaFingerprint, out var hash);
        Assert.True(EnrollmentTokenFormat.TryParse(token, out var secret, out var pin));
        Assert.Equal(_ca.CaFingerprint, pin);
        Assert.Equal(hash, EnrollmentTokenFormat.HashSecret(secret));

        Assert.False(EnrollmentTokenFormat.TryParse("dgs1_short_" + pin, out _, out _));
        Assert.False(EnrollmentTokenFormat.TryParse(token.Replace("dgs1", "dgs2", StringComparison.Ordinal), out _, out _));
    }

    public void Dispose()
    {
        _ca.Dispose();
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private sealed class TempCa : IDisposable
    {
        private readonly string _dir = Path.Combine(Path.GetTempPath(), "dgsiem-pki-" + Guid.NewGuid().ToString("N"));

        public TempCa() => Ca = new CertificateAuthority(
            Options.Create(new PkiOptions { Directory = _dir, AgentHostnames = ["siem-agents.example.com"] }),
            NullLogger<CertificateAuthority>.Instance);

        public CertificateAuthority Ca { get; }

        public void Dispose()
        {
            Ca.Dispose();
            Directory.Delete(_dir, recursive: true);
        }
    }
}
