using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DreaminGeek.Siem.Agent.Buffering;
using DreaminGeek.Siem.Agent.Inputs;
using DreaminGeek.Siem.Agent.Server;
using DreaminGeek.Siem.Core.Agents;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Agent;

/// <summary>
/// Runs the agent: enroll if needed, then the disk-buffer writer, the shipper, the inputs from the
/// server-side config (restarted when it changes), and certificate renewal.
/// </summary>
public sealed partial class AgentService(IOptions<AgentOptions> options, ILoggerFactory loggers, IHostApplicationLifetime lifetime) : BackgroundService
{
    private readonly ILogger _logger = loggers.CreateLogger<AgentService>();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        var store = new AgentStore(o.DataDirectory);

        if (!store.IsEnrolled)
        {
            if (o.ServerUrl is null || string.IsNullOrWhiteSpace(o.EnrollmentToken))
            {
                LogNotEnrolled(_logger, o.DataDirectory);
                lifetime.StopApplication();
                return;
            }
            try
            {
                var name = string.IsNullOrWhiteSpace(o.Name) ? Environment.MachineName.ToLowerInvariant() : o.Name;
                var enrolled = await Enroller.EnrollAsync(store, o.ServerUrl, o.EnrollmentToken, name, stoppingToken);
                LogEnrolled(_logger, name, enrolled.TenantSlug);
            }
            catch (AgentEnrollmentException ex)
            {
                LogEnrollFailed(_logger, ex.Message);
                lifetime.StopApplication();
                return;
            }
        }

        using var server = new ServerClient(store);
        using var buffer = new DiskBuffer(store.BufferDirectory, o.MaxBufferBytes, o.MaxEventsPerSegment, o.SegmentMaxAge);
        var shipper = new Shipper(buffer, server, loggers.CreateLogger<Shipper>());
        var (url, tenant, _) = store.LoadState();
        LogStarting(_logger, ServerClient.Version, url, tenant);

        var writer = buffer.RunWriterAsync(stoppingToken);
        var shipping = shipper.RunAsync(stoppingToken);
        var running = RunInputsAsync(store, server, buffer, stoppingToken);
        var renewal = RenewLoopAsync(store, server, o.RenewBeforeDays, stoppingToken);
        var stats = StatsLoopAsync(buffer, stoppingToken);
        var updates = new AgentUpdater(store, server, loggers.CreateLogger<AgentUpdater>()).RunAsync(stoppingToken);

        try
        {
            await Task.WhenAll(writer, shipping, running, renewal, stats, updates);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // normal shutdown
        }
    }

    /// <summary>Starts inputs from the cached config, then polls the server and restarts them on change.</summary>
    private async Task RunInputsAsync(AgentStore store, ServerClient server, DiskBuffer buffer, CancellationToken ct)
    {
        var config = store.LoadConfig() ?? new AgentConfig();
        var applied = Serialize(config);
        while (!ct.IsCancellationRequested)
        {
            using var inputsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var inputs = StartInputs(config, buffer, server.ClientCertificate, store, inputsCts.Token);

            // Poll until the config changes.
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(config.ConfigPollSeconds, 10, 3600)), ct);
                AgentConfig? fresh;
                try
                {
                    fresh = await server.GetConfigAsync(Status(buffer), ct);
                }
                catch (HttpRequestException ex)
                {
                    LogConfigPollFailed(_logger, ex.Message);
                    continue;
                }
                if (fresh is not null && Serialize(fresh) != applied)
                {
                    LogConfigChanged(_logger);
                    store.SaveConfig(fresh);
                    config = fresh;
                    applied = Serialize(fresh);
                    break;
                }
            }

            await inputsCts.CancelAsync();
            await Task.WhenAll(inputs.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
        }
    }

    private List<Task> StartInputs(AgentConfig config, DiskBuffer buffer, X509Certificate2 certificate, AgentStore store, CancellationToken ct)
    {
        var hints = new SourceHints(config.SourceHints);
        var positions = new FilePositions(store.FilePositionsPath);
        var bookmarks = new EventLogBookmarks(store.EventLogBookmarksPath);
        var tasks = new List<Task>();
        foreach (var input in config.Inputs)
        {
            var logger = loggers.CreateLogger($"DreaminGeek.Siem.Agent.Inputs.{input.Type}");
            Func<Task> run = input.Type switch
            {
                InputType.SyslogUdp => () => new SyslogUdpInput(input, hints, buffer, logger).RunAsync(ct),
                InputType.SyslogTcp => () => new SyslogTcpInput(input, hints, buffer, null, logger).RunAsync(ct),
                InputType.SyslogTls => () => new SyslogTcpInput(input, hints, buffer, certificate, logger).RunAsync(ct),
                InputType.File => () => new FileTailInput(input, buffer, positions, logger).RunAsync(ct),
                InputType.Hec => () => new HecInput(input, buffer, certificate, logger).RunAsync(ct),
                InputType.WindowsEventLog => () =>
                {
                    if (OperatingSystem.IsWindows())
                    {
                        return new WindowsEventLogInput(input, buffer, bookmarks, logger).RunAsync(ct);
                    }
                    LogWindowsOnly(_logger);
                    return Task.CompletedTask;
                },
                _ => () => Task.CompletedTask,
            };
            tasks.Add(Supervise(input, run, ct));
        }
        return tasks;
    }

    /// <summary>Keeps one input running; a bind failure (port in use, no permission) is retried every 30s.</summary>
    private async Task Supervise(InputConfig input, Func<Task> run, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await run();
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException or UnauthorizedAccessException)
            {
                LogInputFailed(_logger, input.Type, input.Port, ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(30), ct).ContinueWith(_ => { }, TaskScheduler.Default);
            }
        }
    }

    private async Task RenewLoopAsync(AgentStore store, ServerClient server, int renewBeforeDays, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            if (server.ClientCertificate.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(renewBeforeDays))
            {
                try
                {
                    var (_, tenant, _) = store.LoadState();
                    var (keyPem, csrPem) = KeyMaterial.NewKeyAndCsr(server.ClientCertificate.GetNameInfo(X509NameType.SimpleName, false));
                    var certPem = await server.RenewAsync(csrPem, ct);
                    store.SaveRenewal(certPem, keyPem);
                    server.Reload();
                    LogRenewed(_logger, tenant, server.ClientCertificate.NotAfter);
                }
                catch (HttpRequestException ex)
                {
                    LogRenewFailed(_logger, ex.Message);
                }
            }
            await Task.Delay(TimeSpan.FromHours(6), ct);
        }
    }

    private async Task StatsLoopAsync(DiskBuffer buffer, CancellationToken ct)
    {
        long dropped = 0, evicted = 0;
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), ct);
            if (buffer.Dropped != dropped || buffer.Evicted != evicted)
            {
                LogDataLoss(_logger, buffer.Dropped - dropped, buffer.Evicted - evicted);
                dropped = buffer.Dropped;
                evicted = buffer.Evicted;
            }
        }
    }

    private static AgentStatusReport? Status(DiskBuffer buffer)
    {
        try
        {
            return buffer.Status();
        }
        catch (IOException)
        {
            return null; // best effort: the config poll matters more
        }
    }

    private static string Serialize(AgentConfig config) => JsonSerializer.Serialize(config, AgentJsonContext.Default.AgentConfig);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The config has a WindowsEventLog input, which only runs on Windows agents; ignoring it")]
    private static partial void LogWindowsOnly(ILogger logger);

    [LoggerMessage(Level = LogLevel.Critical, Message = "Agent is not enrolled. Run 'dg-siem-agent enroll --server <url> --token <token> --name <name>' or set Agent:ServerUrl and Agent:EnrollmentToken. Data directory: {DataDirectory}")]
    private static partial void LogNotEnrolled(ILogger logger, string dataDirectory);

    [LoggerMessage(Level = LogLevel.Information, Message = "Enrolled as {Name} for tenant {Tenant}")]
    private static partial void LogEnrolled(ILogger logger, string name, string tenant);

    [LoggerMessage(Level = LogLevel.Critical, Message = "Enrollment failed: {Reason}")]
    private static partial void LogEnrollFailed(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "dg-siem-agent {Version} starting; server {Server}, tenant {Tenant}")]
    private static partial void LogStarting(ILogger logger, string version, Uri server, string tenant);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not fetch config from server ({Error}); keeping current inputs")]
    private static partial void LogConfigPollFailed(ILogger logger, string error);

    [LoggerMessage(Level = LogLevel.Information, Message = "Config changed on the server; restarting inputs")]
    private static partial void LogConfigChanged(ILogger logger);

    [LoggerMessage(Level = LogLevel.Error, Message = "Input {Type} on port {Port} failed: {Error}. Retrying in 30s")]
    private static partial void LogInputFailed(ILogger logger, InputType type, int port, string error);

    [LoggerMessage(Level = LogLevel.Information, Message = "Renewed agent certificate for tenant {Tenant}; valid until {NotAfter}")]
    private static partial void LogRenewed(ILogger logger, string tenant, DateTime notAfter);

    [LoggerMessage(Level = LogLevel.Error, Message = "Certificate renewal failed: {Error}. Will retry")]
    private static partial void LogRenewFailed(ILogger logger, string error);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Data loss in the last minute: {Dropped} events dropped (writer overloaded), {Evicted} evicted (buffer full)")]
    private static partial void LogDataLoss(ILogger logger, long dropped, long evicted);
}
