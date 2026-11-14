using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Web.Agents;

public sealed class AgentPackageOptions
{
    public const string SectionName = "AgentPackages";

    /// <summary>Uploaded agent versions and their install packages (on the data volume).</summary>
    public string Directory { get; set; } = "/var/lib/dg-siem/agent-packages";

    /// <summary>Versions kept per platform; older ones are deleted when a new one is uploaded.</summary>
    public int Keep { get; set; } = 3;
}

/// <summary>What an agent binary says about itself.</summary>
public sealed record AgentBinaryInfo(string Platform, string Version);

/// <summary>One uploaded agent version for one platform.</summary>
public sealed record AgentPackage(
    string Platform, string Version, string BinarySha256, long BinarySize, string PackageFile, string PackageSha256,
    DateTimeOffset UploadedAt, string? UploadedBy, string? ScriptsSha256 = null)
{
    public bool IsWindows => Platform.StartsWith("win-", StringComparison.Ordinal);
    public string BinaryName => IsWindows ? "dg-siem-agent.exe" : "dg-siem-agent";
}

public sealed class AgentPackageException(string message) : Exception(message);

/// <summary>
/// Agent versions uploaded by an admin: the binary (served to agents updating themselves) and an install package
/// built around it with this server's install scripts (served to new machines with an enrollment token).
/// Layout: <c>{platform}/{version}/{binary, package, package.json}</c>.
/// </summary>
public sealed partial class AgentPackageStore(IOptions<AgentPackageOptions> options, ILogger<AgentPackageStore> logger)
{
    public static readonly string[] Platforms = ["linux-x64", "linux-arm64", "win-x64"];
    private const long MaxUpload = 200L * 1024 * 1024;
    private static readonly byte[] MarkerUtf16 = Encoding.Unicode.GetBytes("DG-SIEM-AGENT-VERSION=");
    private static readonly byte[] MarkerUtf8 = Encoding.UTF8.GetBytes("DG-SIEM-AGENT-VERSION=");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly Lock _lock = new();
    private string Root => options.Value.Directory;

    // ---- Identify ----------------------------------------------------------------------------

    /// <summary>Platform from the executable header (ELF/PE, x64/arm64), version from the marker built into the agent.</summary>
    public static AgentBinaryInfo? Identify(ReadOnlySpan<byte> binary)
    {
        string? platform = null;
        if (binary.Length > 64 && binary[0] == 0x7F && binary[1] == (byte)'E' && binary[2] == (byte)'L' && binary[3] == (byte)'F')
        {
            var machine = BitConverter.ToUInt16(binary[18..20]);
            platform = machine switch { 0x3E => "linux-x64", 0xB7 => "linux-arm64", _ => null };
        }
        else if (binary.Length > 0x40 && binary[0] == (byte)'M' && binary[1] == (byte)'Z')
        {
            var pe = BitConverter.ToInt32(binary[0x3C..0x40]);
            if (pe > 0 && pe + 6 < binary.Length && binary[pe] == (byte)'P' && binary[pe + 1] == (byte)'E')
            {
                var machine = BitConverter.ToUInt16(binary[(pe + 4)..(pe + 6)]);
                platform = machine switch { 0x8664 => "win-x64", 0xAA64 => "win-arm64", _ => null };
            }
        }
        if (platform is null)
        {
            return null;
        }
        var version = MarkerValue(binary, MarkerUtf16, Encoding.Unicode) ?? MarkerValue(binary, MarkerUtf8, Encoding.UTF8);
        return version is not null && System.Version.TryParse(version, out _) ? new AgentBinaryInfo(platform, version) : null;
    }

    private static string? MarkerValue(ReadOnlySpan<byte> binary, byte[] marker, Encoding encoding)
    {
        var at = binary.IndexOf(marker);
        if (at < 0)
        {
            return null;
        }
        var rest = binary.Slice(at + marker.Length, Math.Min(64, binary.Length - at - marker.Length));
        var text = encoding.GetString(rest);
        var end = text.IndexOf(';', StringComparison.Ordinal);
        return end > 0 ? text[..end] : null;
    }

    /// <summary>The agent binary inside an upload: a <c>.tar.gz</c> or <c>.zip</c> package, or the binary itself.</summary>
    public static byte[] ExtractBinary(string fileName, byte[] upload)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentNullException.ThrowIfNull(upload);
        if (upload.Length > 4 && upload[0] == 0x1F && upload[1] == 0x8B)
        {
            using var gzip = new GZipStream(new MemoryStream(upload), CompressionMode.Decompress);
            using var tar = new TarReader(gzip);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile && Path.GetFileName(entry.Name) == "dg-siem-agent" && entry.DataStream is { } data)
                {
                    using var copy = new MemoryStream();
                    data.CopyTo(copy);
                    return copy.ToArray();
                }
            }
            throw new AgentPackageException($"{fileName} has no dg-siem-agent binary in it.");
        }
        if (upload.Length > 4 && upload[0] == (byte)'P' && upload[1] == (byte)'K')
        {
            using var zip = new ZipArchive(new MemoryStream(upload), ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e => Path.GetFileName(e.FullName).Equals("dg-siem-agent.exe", StringComparison.OrdinalIgnoreCase))
                ?? throw new AgentPackageException($"{fileName} has no dg-siem-agent.exe in it.");
            using var stream = entry.Open();
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            return copy.ToArray();
        }
        return upload;
    }

    // ---- Add / list / remove -----------------------------------------------------------------

    public async Task<AgentPackage> AddAsync(string fileName, Stream content, string? uploadedBy, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(content);
        using var buffer = new MemoryStream();
        await content.CopyToAsync(buffer, ct);
        if (buffer.Length > MaxUpload)
        {
            throw new AgentPackageException("That file is too large to be an agent package.");
        }
        byte[] binary;
        try
        {
            binary = ExtractBinary(fileName, buffer.ToArray());
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or FormatException)
        {
            throw new AgentPackageException($"{fileName} couldn't be read: {ex.Message}");
        }
        var info = Identify(binary) ?? throw new AgentPackageException(
            $"{fileName} isn't a DG SIEM agent from version 0.4.0 or later (no version marker found). Upload the .tar.gz or .zip package, or the agent binary.");

        var now = DateTimeOffset.UtcNow;
        var dir = VersionDir(info.Platform, info.Version);
        Directory.CreateDirectory(dir);
        var isWindows = info.Platform.StartsWith("win-", StringComparison.Ordinal);
        var binaryName = isWindows ? "dg-siem-agent.exe" : "dg-siem-agent";
        await File.WriteAllBytesAsync(Path.Combine(dir, binaryName), binary, ct);

        var packageName = $"dg-siem-agent-{info.Version}-{info.Platform}{(isWindows ? ".zip" : ".tar.gz")}";
        var packageBytes = isWindows ? BuildZip(binary, now) : BuildTarGz(binary, now);
        await File.WriteAllBytesAsync(Path.Combine(dir, packageName), packageBytes, ct);

        var package = new AgentPackage(info.Platform, info.Version, Sha256(binary), binary.Length, packageName, Sha256(packageBytes), now, uploadedBy,
            ScriptsSha256(isWindows));
        await File.WriteAllTextAsync(Path.Combine(dir, "package.json"), JsonSerializer.Serialize(package, Json), ct);
        Prune(info.Platform);
        LogAdded(logger, info.Platform, info.Version, uploadedBy ?? "?");
        return package;
    }

    /// <summary>
    /// Rebuilds stored packages whose install scripts are older than the ones in this server build, so a
    /// server update with an installer fix reaches new installs without re-uploading the agents.
    /// The binaries are kept; only the package around them (and so its checksum) changes.
    /// </summary>
    public async Task<int> RefreshScriptsAsync(CancellationToken ct)
    {
        var rebuilt = 0;
        foreach (var package in List())
        {
            var scripts = ScriptsSha256(package.IsWindows);
            var binaryPath = BinaryPath(package);
            if (package.ScriptsSha256 == scripts || !File.Exists(binaryPath))
            {
                continue;
            }
            var binary = await File.ReadAllBytesAsync(binaryPath, ct);
            var bytes = package.IsWindows ? BuildZip(binary, package.UploadedAt) : BuildTarGz(binary, package.UploadedAt);
            var dir = VersionDir(package.Platform, package.Version);
            await File.WriteAllBytesAsync(Path.Combine(dir, package.PackageFile), bytes, ct);
            var updated = package with { PackageSha256 = Sha256(bytes), ScriptsSha256 = scripts };
            await File.WriteAllTextAsync(Path.Combine(dir, "package.json"), JsonSerializer.Serialize(updated, Json), ct);
            LogRebuilt(logger, package.Platform, package.Version);
            rebuilt++;
        }
        return rebuilt;
    }

    /// <summary>Fingerprint of the scripts and units that go into a package next to the binary.</summary>
    private static string ScriptsSha256(bool windows)
    {
        string[] names = windows
            ? ["install.ps1", "LICENSE"]
            : ["install.sh", "dg-siem-agent.service", "dg-siem-agent-update.service", "dg-siem-agent-update.path", "LICENSE"];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var name in names)
        {
            hash.AppendData(Encoding.UTF8.GetBytes(name + "\n"));
            hash.AppendData(Resource(name));
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    /// <summary>Every stored version, newest first within each platform.</summary>
    public IReadOnlyList<AgentPackage> List()
    {
        var all = new List<AgentPackage>();
        if (!Directory.Exists(Root))
        {
            return all;
        }
        foreach (var platform in Directory.GetDirectories(Root))
        {
            foreach (var version in Directory.GetDirectories(platform))
            {
                var meta = Path.Combine(version, "package.json");
                try
                {
                    if (File.Exists(meta) && JsonSerializer.Deserialize<AgentPackage>(File.ReadAllText(meta), Json) is { } package)
                    {
                        all.Add(package);
                    }
                }
                catch (JsonException)
                {
                    // A half-written upload; ignore.
                }
            }
        }
        return all
            .OrderBy(p => p.Platform, StringComparer.Ordinal)
            .ThenByDescending(p => System.Version.TryParse(p.Version, out var v) ? v : new System.Version())
            .ToList();
    }

    public AgentPackage? Latest(string platform) => List().FirstOrDefault(p => p.Platform == platform);

    public AgentPackage? Find(string platform, string version) => List().FirstOrDefault(p => p.Platform == platform && p.Version == version);

    public string BinaryPath(AgentPackage package) => Path.Combine(VersionDir(package.Platform, package.Version), package.BinaryName);

    public string PackagePath(AgentPackage package) => Path.Combine(VersionDir(package.Platform, package.Version), package.PackageFile);

    /// <summary>Removes one version (e.g. a bad build): agents on it stay on it, others get the next newest.</summary>
    public void Remove(string platform, string version)
    {
        var dir = VersionDir(platform, version);
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>True when <paramref name="candidate"/> is a higher version than <paramref name="current"/> (unknown counts as oldest).</summary>
    public static bool IsNewer(string candidate, string? current) =>
        System.Version.TryParse(candidate, out var c) && (!System.Version.TryParse(current ?? "", out var cur) || c > cur);

    private void Prune(string platform)
    {
        lock (_lock)
        {
            foreach (var old in List().Where(p => p.Platform == platform).Skip(Math.Max(1, options.Value.Keep)))
            {
                Remove(old.Platform, old.Version);
            }
        }
    }

    private string VersionDir(string platform, string version)
    {
        if (!Platforms.Contains(platform) && platform != "win-arm64" || !System.Version.TryParse(version, out _))
        {
            throw new AgentPackageException($"Unknown platform or version: {platform} {version}.");
        }
        return Path.Combine(Root, platform, version);
    }

    // ---- Packages ----------------------------------------------------------------------------

    private static byte[] BuildTarGz(byte[] binary, DateTimeOffset time)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        using (var tar = new TarWriter(gzip, TarEntryFormat.Pax))
        {
            void Add(string name, byte[] data, UnixFileMode mode)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(data), Mode = mode, ModificationTime = time };
                tar.WriteEntry(entry);
            }
            const UnixFileMode exec = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
            const UnixFileMode file = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
            Add("dg-siem-agent", binary, exec);
            Add("install.sh", Resource("install.sh"), exec);
            Add("dg-siem-agent.service", Resource("dg-siem-agent.service"), file);
            Add("dg-siem-agent-update.service", Resource("dg-siem-agent-update.service"), file);
            Add("dg-siem-agent-update.path", Resource("dg-siem-agent-update.path"), file);
            Add("LICENSE", Resource("LICENSE"), file);
        }
        return output.ToArray();
    }

    private static byte[] BuildZip(byte[] binary, DateTimeOffset time)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, byte[] data)
            {
                var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
                entry.LastWriteTime = time;
                using var stream = entry.Open();
                stream.Write(data);
            }
            Add("dg-siem-agent.exe", binary);
            Add("install.ps1", Resource("install.ps1"));
            Add("LICENSE", Resource("LICENSE"));
        }
        return output.ToArray();
    }

    /// <summary>The install scripts and units from <c>deploy/agent</c>, embedded at build time.</summary>
    public static byte[] Resource(string name)
    {
        using var stream = typeof(AgentPackageStore).Assembly.GetManifestResourceStream($"agent/{name}")
            ?? throw new InvalidOperationException($"Embedded resource agent/{name} is missing.");
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    public static string Sha256(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    [LoggerMessage(Level = LogLevel.Information, Message = "Agent {Platform} {Version}: package rebuilt with this server's install scripts")]
    private static partial void LogRebuilt(ILogger logger, string platform, string version);

    [LoggerMessage(Level = LogLevel.Information, Message = "Agent {Platform} {Version} uploaded by {User}")]
    private static partial void LogAdded(ILogger logger, string platform, string version, string user);
}
