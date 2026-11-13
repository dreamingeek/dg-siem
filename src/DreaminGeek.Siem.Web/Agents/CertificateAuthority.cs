using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Web.Agents;

/// <summary>
/// DG SIEM's private CA. It signs one server certificate (for the agent port) and one client
/// certificate per enrolled agent. Agents trust only this CA (pinned via the enrollment token),
/// and the server trusts only agent certificates this CA issued.
/// </summary>
public sealed partial class CertificateAuthority : IDisposable
{
    private const string CaCertFile = "ca.crt.pem";
    private const string CaKeyFile = "ca.key.pem";
    private const string ServerCertFile = "agent-server.crt.pem";
    private const string ServerKeyFile = "agent-server.key.pem";

    private static readonly Oid ClientAuth = new("1.3.6.1.5.5.7.3.2");
    private static readonly Oid ServerAuth = new("1.3.6.1.5.5.7.3.1");

    private readonly PkiOptions _options;
    private readonly ILogger<CertificateAuthority> _logger;
    private readonly Lock _gate = new();
    private X509Certificate2? _ca;
    private X509Certificate2? _server;

    public CertificateAuthority(IOptions<PkiOptions> options, ILogger<CertificateAuthority> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>The CA certificate (with private key). Created on first use.</summary>
    public X509Certificate2 CaCertificate
    {
        get
        {
            lock (_gate)
            {
                return _ca ??= LoadOrCreateCa();
            }
        }
    }

    /// <summary>Lowercase hex SHA-256 of the CA certificate; embedded in enrollment tokens.</summary>
    public string CaFingerprint => Convert.ToHexStringLower(CaCertificate.GetCertHash(HashAlgorithmName.SHA256));

    public string CaCertificatePem => CaCertificate.ExportCertificatePem();

    /// <summary>Certificate for the agent port, re-issued if missing, near expiry or hostnames changed.</summary>
    public X509Certificate2 ServerCertificate
    {
        get
        {
            lock (_gate)
            {
                if (_server is null || NeedsRenewal(_server))
                {
                    _server?.Dispose();
                    _server = LoadOrCreateServerCertificate();
                }
                return _server;
            }
        }
    }

    /// <summary>True if <paramref name="name"/> is one of the names agents use to reach the server.</summary>
    public bool IsServerName(string name) =>
        _options.AgentHostnames.Any(h => string.Equals(h.Trim(), name, StringComparison.OrdinalIgnoreCase))
        || string.Equals(name, "localhost", StringComparison.OrdinalIgnoreCase);

    /// <summary>Signs an agent's CSR. Only the CSR's public key is used; subject and extensions are set here.</summary>
    public X509Certificate2 IssueAgentCertificate(string csrPem, Guid agentId, string agentName, string tenantSlug)
    {
        var csr = CertificateRequest.LoadSigningRequestPem(csrPem, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default); // verifies the CSR signature (proof of key possession)

        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(agentName);
        subject.AddOrganizationalUnitName("dg-siem-agent");
        subject.AddOrganizationName(tenantSlug);

        var request = new CertificateRequest(subject.Build(), csr.PublicKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        // serverAuth too: the agent reuses its certificate for its TLS syslog input.
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ClientAuth, ServerAuth], false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"urn:dg-siem:agent:{agentId:D}"));
        san.AddDnsName(agentName);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(CaCertificate, true, false));

        var now = DateTimeOffset.UtcNow;
        return request.Create(CaCertificate, now.AddMinutes(-5), now.AddDays(_options.AgentCertificateDays), NewSerial());
    }

    /// <summary>Lowercase hex SHA-256 thumbprint, the key used to look agents up.</summary>
    public static string Thumbprint(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Convert.ToHexStringLower(certificate.GetCertHash(HashAlgorithmName.SHA256));
    }

    /// <summary>True if <paramref name="certificate"/> chains to this CA and is currently valid.</summary>
    public bool IsIssuedByUs(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(CaCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(ClientAuth);
        return chain.Build(certificate);
    }

    private X509Certificate2 LoadOrCreateCa()
    {
        Directory.CreateDirectory(_options.Directory);
        var certPath = Path.Combine(_options.Directory, CaCertFile);
        var keyPath = Path.Combine(_options.Directory, CaKeyFile);
        if (File.Exists(certPath) && File.Exists(keyPath))
        {
            return X509Certificate2.CreateFromPemFile(certPath, keyPath);
        }

        LogCreatingCa(_logger, _options.Directory);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var request = new CertificateRequest("CN=DG SIEM Agent CA, O=DG SIEM", key, HashAlgorithmName.SHA384);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        using var ca = request.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(20));

        WritePrivate(keyPath, key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(certPath, ca.ExportCertificatePem());
        return X509Certificate2.CreateFromPemFile(certPath, keyPath);
    }

    private X509Certificate2 LoadOrCreateServerCertificate()
    {
        var certPath = Path.Combine(_options.Directory, ServerCertFile);
        var keyPath = Path.Combine(_options.Directory, ServerKeyFile);
        if (File.Exists(certPath) && File.Exists(keyPath))
        {
            var existing = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            if (!NeedsRenewal(existing))
            {
                return existing;
            }
            existing.Dispose();
        }

        LogIssuingServerCert(_logger, _options.AgentHostnames);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={_options.AgentHostnames.FirstOrDefault() ?? "dg-siem"}, O=DG SIEM", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ServerAuth], false));
        request.CertificateExtensions.Add(BuildServerSan());
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(CaCertificate, true, false));

        var now = DateTimeOffset.UtcNow;
        using var issued = request.Create(CaCertificate, now.AddMinutes(-5), now.AddDays(_options.ServerCertificateDays), NewSerial());
        WritePrivate(keyPath, key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(certPath, issued.ExportCertificatePem());
        return X509Certificate2.CreateFromPemFile(certPath, keyPath);
    }

    private X509Extension BuildServerSan()
    {
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in _options.AgentHostnames.Where(n => !string.IsNullOrWhiteSpace(n)))
        {
            if (IPAddress.TryParse(name, out var ip))
            {
                san.AddIpAddress(ip);
            }
            else
            {
                san.AddDnsName(name);
            }
        }
        return san.Build();
    }

    private bool NeedsRenewal(X509Certificate2 cert)
    {
        if (cert.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(30))
        {
            return true;
        }
        var current = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        var wanted = new X509SubjectAlternativeNameExtension(BuildServerSan().RawData);
        return current is null || !current.RawData.AsSpan().SequenceEqual(wanted.RawData);
    }

    private static byte[] NewSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // keep it positive
        return serial;
    }

    private static void WritePrivate(string path, string content)
    {
        File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    public void Dispose()
    {
        _ca?.Dispose();
        _server?.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Creating new DG SIEM agent CA in {Directory}. Back this directory up.")]
    private static partial void LogCreatingCa(ILogger logger, string directory);

    [LoggerMessage(Level = LogLevel.Information, Message = "Issuing agent-port server certificate for {Hostnames}")]
    private static partial void LogIssuingServerCert(ILogger logger, List<string> hostnames);
}
