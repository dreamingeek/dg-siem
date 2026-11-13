using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using DreaminGeek.Siem.Agent.Server;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Web.Agents;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Tests;

public sealed class AgentPackageTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("dgsiem-pkg-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private AgentPackageStore Store(int keep = 3) =>
        new(Options.Create(new AgentPackageOptions { Directory = Path.Combine(_dir, "packages"), Keep = keep }), NullLogger<AgentPackageStore>.Instance);

    /// <summary>Just enough of an ELF/PE file for the header checks, plus the version marker as the AOT compiler stores it (UTF-16).</summary>
    private static byte[] FakeAgent(string platform, string version)
    {
        var bytes = new byte[4096];
        if (platform.StartsWith("linux", StringComparison.Ordinal))
        {
            bytes[0] = 0x7F; bytes[1] = (byte)'E'; bytes[2] = (byte)'L'; bytes[3] = (byte)'F';
            BitConverter.GetBytes((ushort)(platform == "linux-x64" ? 0x3E : 0xB7)).CopyTo(bytes, 18);
        }
        else
        {
            bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
            BitConverter.GetBytes(0x80).CopyTo(bytes, 0x3C);
            bytes[0x80] = (byte)'P'; bytes[0x81] = (byte)'E';
            BitConverter.GetBytes((ushort)0x8664).CopyTo(bytes, 0x84);
        }
        Encoding.Unicode.GetBytes($"DG-SIEM-AGENT-VERSION={version};").CopyTo(bytes, 1000);
        return bytes;
    }

    [Fact]
    public void Binaries_say_what_they_are()
    {
        Assert.Equal(new AgentBinaryInfo("linux-x64", "0.4.0"), AgentPackageStore.Identify(FakeAgent("linux-x64", "0.4.0")));
        Assert.Equal(new AgentBinaryInfo("linux-arm64", "0.4.0"), AgentPackageStore.Identify(FakeAgent("linux-arm64", "0.4.0")));
        Assert.Equal(new AgentBinaryInfo("win-x64", "1.2.3"), AgentPackageStore.Identify(FakeAgent("win-x64", "1.2.3")));

        var noMarker = FakeAgent("linux-x64", "0.4.0");
        Array.Clear(noMarker, 1000, 100);
        Assert.Null(AgentPackageStore.Identify(noMarker)); // a pre-0.4.0 agent, or something else entirely
        Assert.Null(AgentPackageStore.Identify(Encoding.UTF8.GetBytes("#!/bin/sh\necho hi")));
    }

    [Fact]
    public void The_real_agent_build_carries_its_marker()
    {
        // The agent project is built for the tests, so its marker must be findable in the assembly or AOT binary.
        // (The test host loads the managed dll; the marker string is in it either way.)
        var dll = typeof(AgentUpdater).Assembly.Location;
        var bytes = File.ReadAllBytes(dll);
        var marker = Encoding.Unicode.GetBytes("DG-SIEM-AGENT-VERSION=");
        Assert.True(bytes.AsSpan().IndexOf(marker) >= 0, "BuildInfo.Marker isn't in the agent assembly");
    }

    [Fact]
    public void Uploads_can_be_packages_or_the_binary()
    {
        var binary = FakeAgent("linux-x64", "0.4.0");
        Assert.Equal(binary, AgentPackageStore.ExtractBinary("dg-siem-agent", binary));

        using var tgz = new MemoryStream();
        using (var gz = new GZipStream(tgz, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gz))
        {
            tar.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "dg-siem-agent/"));
            tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "dg-siem-agent/install.sh") { DataStream = new MemoryStream("x"u8.ToArray()) });
            tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "dg-siem-agent/dg-siem-agent") { DataStream = new MemoryStream(binary) });
        }
        Assert.Equal(binary, AgentPackageStore.ExtractBinary("dg-siem-agent-0.4.0-linux-x64.tar.gz", tgz.ToArray()));

        var exe = FakeAgent("win-x64", "0.4.0");
        using var zip = new MemoryStream();
        using (var archive = new ZipArchive(zip, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var entry = archive.CreateEntry("dg-siem-agent.exe").Open();
            entry.Write(exe);
        }
        Assert.Equal(exe, AgentPackageStore.ExtractBinary("dg-siem-agent-win-x64.zip", zip.ToArray()));

        using var emptyZip = new MemoryStream();
        using (new ZipArchive(emptyZip, ZipArchiveMode.Create, leaveOpen: true))
        {
        }
        Assert.Throws<AgentPackageException>(() => AgentPackageStore.ExtractBinary("other.zip", emptyZip.ToArray()));
    }

    [Fact]
    public async Task Uploads_become_install_packages_with_this_servers_scripts()
    {
        var store = Store();
        var binary = FakeAgent("linux-x64", "0.4.0");
        var linux = await store.AddAsync("dg-siem-agent", new MemoryStream(binary), "jdoe", CancellationToken.None);
        Assert.Equal("dg-siem-agent-0.4.0-linux-x64.tar.gz", linux.PackageFile);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(binary)), linux.BinarySha256);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(store.PackagePath(linux)))), linux.PackageSha256);
        Assert.Equal(binary, File.ReadAllBytes(store.BinaryPath(linux)));

        // The package unpacks flat, with an executable agent and installer and the update units.
        var files = new Dictionary<string, (UnixFileMode Mode, byte[] Data)>();
        await using (var gz = new GZipStream(File.OpenRead(store.PackagePath(linux)), CompressionMode.Decompress))
        await using (var tar = new TarReader(gz))
        {
            while (await tar.GetNextEntryAsync() is { } entry)
            {
                using var data = new MemoryStream();
                entry.DataStream?.CopyTo(data);
                files[entry.Name] = (entry.Mode, data.ToArray());
            }
        }
        Assert.Equal(["LICENSE", "dg-siem-agent", "dg-siem-agent-update.path", "dg-siem-agent-update.service", "dg-siem-agent.service", "install.sh"], files.Keys.Order(StringComparer.Ordinal));
        Assert.True(files["dg-siem-agent"].Mode.HasFlag(UnixFileMode.UserExecute));
        Assert.True(files["install.sh"].Mode.HasFlag(UnixFileMode.OtherExecute));
        Assert.Contains("dg-siem-agent-update.path", Encoding.UTF8.GetString(files["install.sh"].Data), StringComparison.Ordinal);
        Assert.Contains("self-update", Encoding.UTF8.GetString(files["dg-siem-agent-update.service"].Data), StringComparison.Ordinal);

        var windows = await store.AddAsync("dg-siem-agent-win-x64.zip", new MemoryStream(FakeAgent("win-x64", "0.4.0")), "jdoe", CancellationToken.None);
        using (var zip = ZipFile.OpenRead(store.PackagePath(windows)))
        {
            Assert.Equal(["LICENSE", "dg-siem-agent.exe", "install.ps1"], zip.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal));
        }
        Assert.Equal(["linux-x64", "win-x64"], store.List().Select(p => p.Platform));
    }

    [Fact]
    public async Task Newest_version_wins_and_old_ones_are_pruned()
    {
        var store = Store(keep: 2);
        foreach (var v in new[] { "0.4.0", "0.10.0", "0.5.0" })
        {
            await store.AddAsync("a", new MemoryStream(FakeAgent("linux-x64", v)), null, CancellationToken.None);
        }
        Assert.Equal(["0.10.0", "0.5.0"], store.List().Select(p => p.Version)); // numeric, not text, order; 0.4.0 pruned
        Assert.Equal("0.10.0", store.Latest("linux-x64")!.Version);
        Assert.Null(store.Latest("win-x64"));

        store.Remove("linux-x64", "0.10.0");
        Assert.Equal("0.5.0", store.Latest("linux-x64")!.Version);

        Assert.True(AgentPackageStore.IsNewer("0.4.0", "0.3.1"));
        Assert.True(AgentPackageStore.IsNewer("0.4.0", null));
        Assert.False(AgentPackageStore.IsNewer("0.4.0", "0.4.0"));
        Assert.False(AgentPackageStore.IsNewer("0.4.0", "0.10.0"));
    }

    [Fact]
    public async Task Updates_must_match_the_checksum_and_report_their_version()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // uses a shell script as the "binary"
        }
        var path = Path.Combine(_dir, "new-agent");
        var script = "#!/bin/sh\necho 0.9.0\n"u8.ToArray();
        void Write() => File.WriteAllBytes(path, script);
        var sha = Convert.ToHexStringLower(SHA256.HashData(script));

        Write();
        await AgentUpdater.VerifyAsync(new AgentUpdateInfo("0.9.0", "linux-x64", sha, script.Length), path, CancellationToken.None);
        Assert.True(File.Exists(path));

        Write();
        await Assert.ThrowsAsync<InvalidDataException>(() => AgentUpdater.VerifyAsync(new AgentUpdateInfo("0.9.0", "linux-x64", new string('0', 64), script.Length), path, CancellationToken.None));
        Assert.False(File.Exists(path)); // a bad download is deleted

        Write();
        var ex = await Assert.ThrowsAsync<InvalidDataException>(() => AgentUpdater.VerifyAsync(new AgentUpdateInfo("1.0.0", "linux-x64", sha, script.Length), path, CancellationToken.None));
        Assert.Contains("reported '0.9.0'", ex.Message, StringComparison.Ordinal);
    }
}
