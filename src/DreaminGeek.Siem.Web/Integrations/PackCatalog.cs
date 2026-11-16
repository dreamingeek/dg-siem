using System.Reflection;
using System.Text.RegularExpressions;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Web.Integrations;

public sealed class PackOptions
{
    public const string SectionName = "Packs";

    /// <summary>Folder for your own packs: one <c>pack.yaml</c> per sub-folder (or <c>*.yaml</c> files). Read at startup and on Reload.</summary>
    public string Directory { get; set; } = "/var/lib/dg-siem/packs";
}

/// <summary>A pack file that couldn't be used, and why.</summary>
public sealed record PackProblem(string Source, string Message);

/// <summary>The packs available on this server: the built-in ones plus any in the packs folder.</summary>
public sealed partial class PackCatalog(IOptions<PackOptions> options, IQueryParser parser, ILogger<PackCatalog> logger)
{
    private (IReadOnlyList<IntegrationPack> Packs, IReadOnlyList<PackProblem> Problems)? _loaded;
    private readonly Lock _lock = new();

    /// <summary>Where your own packs go.</summary>
    public string Folder => options.Value.Directory;

    public IReadOnlyList<IntegrationPack> Packs => Load().Packs;

    public IReadOnlyList<PackProblem> Problems => Load().Problems;

    public IntegrationPack? Find(string id) => Packs.FirstOrDefault(p => p.Id == id);

    /// <summary>Reads the packs folder again (after adding or changing a pack file).</summary>
    public void Reload()
    {
        lock (_lock)
        {
            _loaded = null;
        }
        Load();
    }

    private (IReadOnlyList<IntegrationPack> Packs, IReadOnlyList<PackProblem> Problems) Load()
    {
        lock (_lock)
        {
            return _loaded ??= Read();
        }
    }

    private (IReadOnlyList<IntegrationPack>, IReadOnlyList<PackProblem>) Read()
    {
        var packs = new List<IntegrationPack>();
        var problems = new List<PackProblem>();
        void Add(string source, Func<string> read)
        {
            try
            {
                var pack = PackContent.Parse(read());
                pack.Source = source;
                Validate(pack, parser);
                if (packs.Any(p => p.Id == pack.Id))
                {
                    throw new PackException($"Another pack already has the id \"{pack.Id}\".");
                }
                packs.Add(pack);
            }
            catch (Exception ex) when (ex is PackException or YamlDotNet.Core.YamlException or IOException or UnauthorizedAccessException)
            {
                var message = ex is YamlDotNet.Core.YamlException y ? $"Line {y.Start.Line}: {y.InnerException?.Message ?? y.Message}" : ex.Message;
                problems.Add(new PackProblem(source, message));
                LogBadPack(logger, source, message);
            }
        }

        var assembly = typeof(PackCatalog).Assembly;
        foreach (var name in assembly.GetManifestResourceNames().Where(n => n.StartsWith("packs/", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            Add("built-in", () => ReadResource(assembly, name));
        }

        var folder = options.Value.Directory;
        if (!string.IsNullOrWhiteSpace(folder) && Directory.Exists(folder))
        {
            var files = Directory.EnumerateFiles(folder, "*.yaml", SearchOption.TopDirectoryOnly)
                .Concat(Directory.EnumerateDirectories(folder).Select(d => Path.Combine(d, "pack.yaml")).Where(File.Exists))
                .Order(StringComparer.Ordinal);
            foreach (var file in files)
            {
                Add(file, () => File.ReadAllText(file));
            }
        }
        return (packs.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(), problems);
    }

    private static string ReadResource(Assembly assembly, string name)
    {
        using var stream = assembly.GetManifestResourceStream(name) ?? throw new PackException("Missing resource.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>Checks everything a pack would create, so problems show when it's loaded rather than when it's installed.</summary>
    public static void Validate(IntegrationPack pack, IQueryParser parser)
    {
        ArgumentNullException.ThrowIfNull(pack);
        if (!PackId().IsMatch(pack.Id ?? string.Empty))
        {
            throw new PackException($"\"{pack.Id}\" isn't a pack id: use lower-case letters, digits and dashes (up to 64).");
        }
        if (string.IsNullOrWhiteSpace(pack.Name) || pack.Name.Length > 80)
        {
            throw new PackException($"{pack.Id}: give the pack a name (up to 80 characters).");
        }
        if (pack.Version < 1)
        {
            throw new PackException($"{pack.Id}: version must be 1 or more.");
        }
        pack.Setup ??= new PackSetup();
        pack.Setup.Steps ??= [];
        pack.Dashboards ??= [];
        pack.Alerts ??= [];
        pack.Category = string.IsNullOrWhiteSpace(pack.Category) ? "Other" : pack.Category.Trim();

        void Search(string what, string query, bool placeholders)
        {
            if (string.IsNullOrWhiteSpace(query))
            {
                throw new PackException($"{pack.Id}: {what} needs a search.");
            }
            if (!placeholders && query.Contains("{{", StringComparison.Ordinal))
            {
                // Dashboards and alerts are shared by every tenant, so they can't depend on one tenant's values.
                throw new PackException($"{pack.Id}: {what}: placeholders like {{{{token}}}} only work in the setup.");
            }
            try
            {
                parser.Parse(query);
            }
            catch (QueryParseException ex)
            {
                throw new PackException($"{pack.Id}: {what}: {ex.Message}");
            }
        }

        if (pack.Setup.Input is { Count: > 0 })
        {
            var json = PackContent.InputJson(pack, "pack-validation-token");
            try
            {
                AdminService.ParseAndValidateConfig($$"""{"inputs":[{{json}}]}""");
            }
            catch (AdminException ex)
            {
                throw new PackException($"{pack.Id}: setup input: {ex.Message}");
            }
        }
        if (pack.Receiving is { } receiving)
        {
            Search("receiving", receiving.Search, placeholders: false);
            try
            {
                AlertEvaluator.ParseLookback(receiving.Within);
            }
            catch (AlertRuleException ex)
            {
                throw new PackException($"{pack.Id}: receiving.within: {ex.Message}");
            }
        }

        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var d in pack.Dashboards)
        {
            if (!ItemKey().IsMatch(d.Key ?? string.Empty) || !keys.Add("d:" + d.Key))
            {
                throw new PackException($"{pack.Id}: each dashboard needs its own key (letters, digits, dashes): \"{d.Key}\".");
            }
            if (string.IsNullOrWhiteSpace(d.Name) || d.Name.Length > 120)
            {
                throw new PackException($"{pack.Id}: dashboard {d.Key} needs a name (up to 120 characters).");
            }
            if (!DashboardsRange(d.TimeRange))
            {
                throw new PackException($"{pack.Id}: dashboard {d.Key}: timeRange must be one of -15m, -1h, -4h, -24h, -7d, -30d.");
            }
            if (d.Panels is not { Count: > 0 })
            {
                throw new PackException($"{pack.Id}: dashboard {d.Key} has no panels.");
            }
            foreach (var p in d.Panels)
            {
                if (string.IsNullOrWhiteSpace(p.Title))
                {
                    throw new PackException($"{pack.Id}: dashboard {d.Key}: every panel needs a title.");
                }
                Search($"panel \"{p.Title}\"", p.Search, placeholders: false);
                PackContent.Kind(p.Kind ?? string.Empty);
                if ((p.X is null) != (p.Y is null) || p.X is < 0 or > 11 || p.Y is < 0)
                {
                    throw new PackException($"{pack.Id}: dashboard {d.Key}: panel \"{p.Title}\" needs both x (0-11) and y, or neither.");
                }
                PackContent.Unit(p.Unit ?? string.Empty);
            }
        }
        foreach (var a in pack.Alerts)
        {
            if (!ItemKey().IsMatch(a.Key ?? string.Empty) || !keys.Add("a:" + a.Key))
            {
                throw new PackException($"{pack.Id}: each alert needs its own key (letters, digits, dashes): \"{a.Key}\".");
            }
            if (string.IsNullOrWhiteSpace(a.Name) || a.Name.Length > 200)
            {
                throw new PackException($"{pack.Id}: alert {a.Key} needs a name (up to 200 characters).");
            }
            Search($"alert \"{a.Name}\"", a.Search, placeholders: false);
            try
            {
                AlertEvaluator.ParseLookback(a.TimeRange);
                AlertRunner.ParseSchedule(a.Schedule);
            }
            catch (AlertRuleException ex)
            {
                throw new PackException($"{pack.Id}: alert {a.Key}: {ex.Message}");
            }
            PackContent.Condition(a.Condition ?? string.Empty);
            PackContent.Trigger(a.Trigger ?? string.Empty);
            PackContent.Severity(a.Severity ?? string.Empty);
            if (a.Threshold < 0 || a.SuppressMinutes < 0)
            {
                throw new PackException($"{pack.Id}: alert {a.Key}: threshold and suppressMinutes can't be negative.");
            }
        }
    }

    private static bool DashboardsRange(string range) => Dashboards.DashboardService.Ranges.Any(r => r.Value == range);

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,63}$")]
    private static partial Regex PackId();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")]
    private static partial Regex ItemKey();

    [LoggerMessage(Level = LogLevel.Warning, Message = "Integration pack {Source} can't be used: {Problem}")]
    private static partial void LogBadPack(ILogger logger, string source, string problem);
}
