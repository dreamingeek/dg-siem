using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Server;

/// <summary>Files under the data directory: key, certificate, pinned CA, enrollment state and cached config.</summary>
public sealed class AgentStore(string dataDirectory)
{
    public string KeyPath => Path.Combine(dataDirectory, "agent.key.pem");
    public string CertPath => Path.Combine(dataDirectory, "agent.crt.pem");
    public string CaPath => Path.Combine(dataDirectory, "ca.crt.pem");
    public string StatePath => Path.Combine(dataDirectory, "state.txt");
    public string ConfigPath => Path.Combine(dataDirectory, "config.json");
    public string BufferDirectory => Path.Combine(dataDirectory, "buffer");
    public string FilePositionsPath => Path.Combine(dataDirectory, "file-positions.json");
    public string EventLogBookmarksPath => Path.Combine(dataDirectory, "eventlog-bookmarks.json");
    public string UpdateDirectory => Path.Combine(dataDirectory, "update");

    public bool IsEnrolled => File.Exists(KeyPath) && File.Exists(CertPath) && File.Exists(CaPath) && File.Exists(StatePath);

    public X509Certificate2 LoadClientCertificate() => UsableForTls(X509Certificate2.CreateFromPemFile(CertPath, KeyPath));

    /// <summary>
    /// A certificate loaded from PEM has an ephemeral private key, which Windows' TLS stack (SChannel) can't use:
    /// mTLS to the server, the TLS syslog and HTTPS HEC inputs all fail with "The SSL connection could not be
    /// established". Round-tripping through PKCS#12 gives the key a form SChannel accepts. Linux uses it as is.
    /// </summary>
    public static X509Certificate2 UsableForTls(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!OperatingSystem.IsWindows())
        {
            return certificate;
        }
        using (certificate)
        {
            return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), password: null);
        }
    }

    public X509Certificate2 LoadCa() => X509CertificateLoader.LoadCertificateFromFile(CaPath);

    /// <summary>Server URL recorded at enrollment (line 1), tenant (line 2), agent id (line 3).</summary>
    public (Uri ServerUrl, string Tenant, string AgentId) LoadState()
    {
        var lines = File.ReadAllLines(StatePath);
        return (new Uri(lines[0]), lines[1], lines[2]);
    }

    public void SaveEnrollment(Uri serverUrl, EnrollResponse response, string keyPem)
    {
        Directory.CreateDirectory(dataDirectory);
        WriteAtomic(KeyPath, keyPem, secret: true);
        WriteAtomic(CertPath, response.CertificatePem);
        WriteAtomic(CaPath, response.CaCertificatePem);
        WriteAtomic(StatePath, $"{serverUrl}\n{response.TenantSlug}\n{response.AgentId}\n");
        SaveConfig(response.Config);
    }

    public void SaveRenewal(string certificatePem, string keyPem)
    {
        // Key first: if we crash in between, the old cert + new key mismatch is caught on load and
        // the agent re-enrolls; writing the cert first could leave an unusable pair silently.
        WriteAtomic(KeyPath + ".new", keyPem, secret: true);
        WriteAtomic(CertPath + ".new", certificatePem);
        File.Move(KeyPath + ".new", KeyPath, overwrite: true);
        File.Move(CertPath + ".new", CertPath, overwrite: true);
    }

    public AgentConfig? LoadConfig() =>
        File.Exists(ConfigPath) ? JsonSerializer.Deserialize(File.ReadAllText(ConfigPath), AgentJsonContext.Default.AgentConfig) : null;

    public void SaveConfig(AgentConfig config) =>
        WriteAtomic(ConfigPath, JsonSerializer.Serialize(config, AgentJsonContext.Default.AgentConfig));

    private static void WriteAtomic(string path, string content, bool secret = false)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        if (secret && !OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.Move(tmp, path, overwrite: true);
    }
}
