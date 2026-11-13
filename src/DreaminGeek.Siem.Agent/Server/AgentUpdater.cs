using System.Diagnostics;
using System.Security.Cryptography;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Server;

/// <summary>
/// Automatic updates. The agent asks the server every 15 minutes whether there's a newer version for its platform.
/// <list type="bullet">
/// <item>Windows (the service runs as SYSTEM): download, check SHA-256 and <c>--version</c>, rename the running exe
/// aside, put the new one in its place and restart the service.</item>
/// <item>Linux (the service runs unprivileged and can't write <c>/usr/local/bin</c>): create
/// <c>update/requested</c>; systemd's <c>dg-siem-agent-update.path</c> then runs <c>dg-siem-agent self-update</c>
/// as root, which fetches and checks the new version itself (<see cref="SelfUpdateAsync"/>).</item>
/// </list>
/// </summary>
public sealed partial class AgentUpdater(AgentStore store, ServerClient server, ILogger logger)
{
    private static readonly TimeSpan FirstCheck = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RequestAgain = TimeSpan.FromHours(6);
    public const string LinuxBinary = "/usr/local/bin/dg-siem-agent";
    private const string UpdatePathUnit = "/etc/systemd/system/dg-siem-agent-update.path";
    private bool _warnedNoUnits;

    public async Task RunAsync(CancellationToken ct)
    {
        CleanUpAfterUpdate();
        await Task.Delay(FirstCheck + TimeSpan.FromSeconds(Random.Shared.Next(60)), ct);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (await server.GetUpdateAsync(ct) is { } update)
                {
                    if (OperatingSystem.IsWindows())
                    {
                        await ApplyOnWindowsAsync(update, ct);
                    }
                    else
                    {
                        RequestOnLinux(update);
                    }
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or InvalidDataException)
            {
                LogFailed(logger, ex.Message);
            }
            await Task.Delay(Interval + TimeSpan.FromSeconds(Random.Shared.Next(-120, 120)), ct);
        }
    }

    // ---- Windows -----------------------------------------------------------------------------

    private async Task ApplyOnWindowsAsync(AgentUpdateInfo update, CancellationToken ct)
    {
        var current = Environment.ProcessPath ?? throw new IOException("Can't tell where the agent runs from.");
        Directory.CreateDirectory(store.UpdateDirectory);
        var staged = Path.Combine(store.UpdateDirectory, "dg-siem-agent.exe");
        await DownloadVerifiedAsync(server, update, staged, ct);

        var old = current + ".old";
        if (File.Exists(old))
        {
            File.Delete(old);
        }
        // Windows lets a running exe be renamed (not overwritten), so: aside, then the new one in its place.
        File.Move(current, old);
        try
        {
            File.Move(staged, current);
        }
        catch
        {
            File.Move(old, current);
            throw;
        }
        LogInstalled(logger, ServerClient.Version, update.Version);

        // A service can't restart itself in-process: a detached helper stops and starts it once we're gone.
        Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 3 127.0.0.1 >nul & net stop dg-siem-agent & net start dg-siem-agent")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });
    }

    /// <summary>The renamed previous exe can only be deleted once it's no longer running.</summary>
    private static void CleanUpAfterUpdate()
    {
        if (OperatingSystem.IsWindows() && Environment.ProcessPath is { } current && File.Exists(current + ".old"))
        {
            try
            {
                File.Delete(current + ".old");
            }
            catch (IOException)
            {
                // Still locked; next start.
            }
            catch (UnauthorizedAccessException)
            {
                // Same.
            }
        }
    }

    // ---- Linux -------------------------------------------------------------------------------

    private void RequestOnLinux(AgentUpdateInfo update)
    {
        if (!File.Exists(UpdatePathUnit))
        {
            if (!_warnedNoUnits)
            {
                LogNoUnits(logger, update.Version);
                _warnedNoUnits = true;
            }
            return;
        }
        Directory.CreateDirectory(store.UpdateDirectory);
        var request = Path.Combine(store.UpdateDirectory, "requested");
        var attempted = Path.Combine(store.UpdateDirectory, "attempted");
        // One request per version every few hours: if root's install failed, don't loop on it.
        if (File.Exists(attempted) && File.ReadAllText(attempted).Trim() == update.Version && DateTime.UtcNow - File.GetLastWriteTimeUtc(attempted) < RequestAgain)
        {
            return;
        }
        File.WriteAllText(attempted, update.Version);
        File.WriteAllText(request, update.Version);
        LogRequested(logger, update.Version);
    }

    /// <summary>
    /// <c>dg-siem-agent self-update</c>, run as root by <c>dg-siem-agent-update.service</c>: ask the server (with the
    /// agent's certificate), download and verify, replace <paramref name="installPath"/>, restart the service.
    /// </summary>
    /// <returns>Process exit code.</returns>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public static async Task<int> SelfUpdateAsync(AgentStore store, string installPath, bool restart, TextWriter output, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(output);
        var request = Path.Combine(store.UpdateDirectory, "requested");
        try
        {
            if (!store.IsEnrolled)
            {
                output.WriteLine("Not enrolled; nothing to update.");
                return 1;
            }
            using var server = new ServerClient(store);
            var update = await server.GetUpdateAsync(ct);
            if (update is null)
            {
                output.WriteLine($"dg-siem-agent {ServerClient.Version} is current.");
                return 0;
            }
            Directory.CreateDirectory(store.UpdateDirectory);
            var staged = Path.Combine(store.UpdateDirectory, "dg-siem-agent.download");
            await DownloadVerifiedAsync(server, update, staged, ct);

            // Same filesystem: write next to the target and rename over it (atomic; the running agent keeps its inode).
            var next = installPath + ".new";
            File.Copy(staged, next, overwrite: true);
            File.SetUnixFileMode(next, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            File.Move(next, installPath, overwrite: true);
            File.Delete(staged);
            output.WriteLine($"Installed dg-siem-agent {update.Version} (was {ServerClient.Version}).");
            if (restart)
            {
                using var systemctl = Process.Start(new ProcessStartInfo("systemctl", "restart dg-siem-agent") { UseShellExecute = false });
                if (systemctl is not null)
                {
                    await systemctl.WaitForExitAsync(ct);
                }
            }
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            output.WriteLine($"Update failed: {ex.Message}");
            return 1;
        }
        finally
        {
            // Always clear the request, or the path unit would keep re-running us.
            try
            {
                File.Delete(request);
            }
            catch (IOException)
            {
                // Nothing more to do.
            }
        }
    }

    // ---- Shared ------------------------------------------------------------------------------

    /// <summary>Downloads to <paramref name="path"/>, checks size and SHA-256, and that the binary runs and reports the expected version.</summary>
    public static async Task DownloadVerifiedAsync(ServerClient server, AgentUpdateInfo update, string path, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(update);
        await using (var file = File.Create(path))
        {
            await server.DownloadUpdateAsync(update, file, ct);
        }
        await VerifyAsync(update, path, ct);
    }

    public static async Task VerifyAsync(AgentUpdateInfo update, string path, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(update);
        var bytes = await File.ReadAllBytesAsync(path, ct);
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (bytes.Length != update.Size || !string.Equals(hash, update.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(path);
            throw new InvalidDataException($"The downloaded {update.Version} doesn't match the server's checksum; not installing it.");
        }
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        using var check = Process.Start(new ProcessStartInfo(path, "--version") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })
            ?? throw new InvalidDataException("The new version wouldn't start.");
        var reported = (await check.StandardOutput.ReadToEndAsync(ct)).Trim();
        await check.WaitForExitAsync(ct);
        if (check.ExitCode != 0 || reported != update.Version)
        {
            File.Delete(path);
            throw new InvalidDataException($"The new binary reported '{reported}' instead of {update.Version}; not installing it.");
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Automatic update check failed: {Reason}")]
    private static partial void LogFailed(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Updated from {From} to {To}; restarting")]
    private static partial void LogInstalled(ILogger logger, string from, string to);

    [LoggerMessage(Level = LogLevel.Information, Message = "Version {Version} is available; asked systemd to install it")]
    private static partial void LogRequested(ILogger logger, string version);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Version {Version} is available, but automatic updates aren't set up on this machine. Run install.sh from a 0.4.0 or later package once to enable them.")]
    private static partial void LogNoUnits(ILogger logger, string version);
}
