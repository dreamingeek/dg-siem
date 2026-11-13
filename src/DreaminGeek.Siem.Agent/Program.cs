using DreaminGeek.Siem.Agent;
using DreaminGeek.Siem.Agent.Server;

// `dg-siem-agent --version`: the version alone (the updater checks a new binary with it before swapping it in).
if (args is ["--version"])
{
    Console.WriteLine(BuildInfo.Version);
    return 0;
}
if (args is ["--build-info"])
{
    Console.WriteLine($"{BuildInfo.Marker} {DreaminGeek.Siem.Agent.Server.ServerClient.Platform}");
    return 0;
}

// `dg-siem-agent self-update [--data-dir DIR] [--install-path FILE] [--no-restart]`: run as root by dg-siem-agent-update.service (Linux).
if (args is ["self-update", ..])
{
    if (OperatingSystem.IsWindows())
    {
        Console.Error.WriteLine("On Windows the service updates itself.");
        return 2;
    }
    var dirIndex = Array.IndexOf(args, "--data-dir");
    var updateStore = new AgentStore(dirIndex >= 0 && dirIndex + 1 < args.Length ? args[dirIndex + 1] : AgentOptions.DefaultDataDirectory);
    var pathIndex = Array.IndexOf(args, "--install-path");
    var installPath = pathIndex >= 0 && pathIndex + 1 < args.Length ? args[pathIndex + 1] : AgentUpdater.LinuxBinary;
    return await AgentUpdater.SelfUpdateAsync(updateStore, installPath, restart: !args.Contains("--no-restart"), Console.Out, CancellationToken.None);
}

// `dg-siem-agent enroll --server https://host:8443 --token dgs1_... [--name acme-log-col] [--data-dir /var/lib/dg-siem-agent]`
if (args is ["enroll", ..])
{
    string? Arg(string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    var server = Arg("--server");
    var token = Arg("--token");
    if (server is null || token is null)
    {
        Console.Error.WriteLine("usage: dg-siem-agent enroll --server <https://host:8443> --token <token> [--name <name>] [--data-dir <dir>]");
        return 2;
    }
    var name = Arg("--name") ?? Environment.MachineName.ToLowerInvariant();
    var store = new AgentStore(Arg("--data-dir") ?? AgentOptions.DefaultDataDirectory);
    try
    {
        var result = await Enroller.EnrollAsync(store, new Uri(server), token, name, CancellationToken.None);
        Console.WriteLine($"Enrolled '{name}' for tenant '{result.TenantSlug}' (agent {result.AgentId}). Start the service: " +
            (OperatingSystem.IsWindows() ? "Start-Service dg-siem-agent" : "systemctl enable --now dg-siem-agent"));
        return 0;
    }
    catch (AgentEnrollmentException ex)
    {
        Console.Error.WriteLine($"error: {ex.Message}");
        return 1;
    }
}

var builder = Host.CreateApplicationBuilder(args);

// System-wide config for installs: /etc/dg-siem-agent/appsettings.json, or %ProgramData%\DG SIEM\Agent\appsettings.json
builder.Configuration.AddJsonFile(AgentOptions.SystemSettingsPath, optional: true, reloadOnChange: false);

// Each is a no-op unless running under that service manager.
builder.Services.AddSystemd();
builder.Services.AddWindowsService(o => o.ServiceName = "dg-siem-agent");
builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));
builder.Services.AddHostedService<AgentService>();

var host = builder.Build();
await host.RunAsync();
return 0;
