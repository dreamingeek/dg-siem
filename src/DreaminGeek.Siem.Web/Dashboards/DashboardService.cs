using System.Diagnostics;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Admin;
using DreaminGeek.Siem.Web.Search;
using DreaminGeek.Siem.Web.Security;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Dashboards;

public sealed record DashboardSummary(Guid Id, string Name, string? Description, int Panels, DateTimeOffset UpdatedAt);

/// <summary>A dashboard being viewed or edited.</summary>
public sealed class DashboardModel
{
    public Guid Id { get; init; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string TimeRange { get; set; } = "-24h";
    public int RefreshSeconds { get; set; }
    public List<DashboardPanel> Panels { get; set; } = [];
}

/// <summary>Dashboards (global admins only) and running their panels' searches.</summary>
public sealed class DashboardService(IDbContextFactory<SiemDbContext> dbFactory, SearchService search, IQueryParser parser, TenantAccess access)
{
    public static readonly (string Value, string Label)[] Ranges =
        [("-15m", "Last 15 minutes"), ("-1h", "Last hour"), ("-4h", "Last 4 hours"), ("-24h", "Last 24 hours"), ("-7d", "Last 7 days"), ("-30d", "Last 30 days")];

    public static readonly (int Seconds, string Label)[] RefreshOptions =
        [(0, "Off"), (60, "Every minute"), (300, "Every 5 minutes"), (900, "Every 15 minutes")];

    public async Task<IReadOnlyList<DashboardSummary>> ListAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can use dashboards.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var rows = await db.Dashboards.AsNoTracking().OrderBy(d => d.Name).ToListAsync(ct);
        return rows.Select(d => new DashboardSummary(d.Id, d.Name, d.Description, PanelJson.Deserialize(d.LayoutJson).Count, d.UpdatedAt)).ToList();
    }

    public async Task<DashboardModel?> GetAsync(UserAccess caller, Guid id, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can use dashboards.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var d = await db.Dashboards.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        return d is null ? null : new DashboardModel
        {
            Id = d.Id,
            Name = d.Name,
            Description = d.Description,
            TimeRange = d.TimeRange.Length > 0 ? d.TimeRange : "-24h",
            RefreshSeconds = d.RefreshSeconds,
            Panels = PanelJson.Deserialize(d.LayoutJson),
        };
    }

    public async Task<Guid> CreateAsync(UserAccess caller, string name, string? description, IEnumerable<DashboardPanel>? panels, string timeRange, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can use dashboards.", ct);
        name = (name ?? string.Empty).Trim();
        if (name.Length is 0 or > 120)
        {
            throw new AdminException("Give the dashboard a name (up to 120 characters).");
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        if (await db.Dashboards.AnyAsync(d => d.Name == name, ct))
        {
            throw new AdminException($"There's already a dashboard named \"{name}\".");
        }
        var dashboard = new Dashboard
        {
            Id = Guid.NewGuid(),
            Name = name,
            Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            TimeRange = timeRange,
            LayoutJson = PanelJson.Serialize(panels ?? []),
            OwnerId = caller.UserId,
        };
        db.Dashboards.Add(dashboard);
        await db.SaveChangesAsync(ct);
        return dashboard.Id;
    }

    /// <summary>Saves name, description, defaults and every panel (position, size and settings).</summary>
    public async Task SaveAsync(UserAccess caller, DashboardModel model, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can use dashboards.", ct);
        ArgumentNullException.ThrowIfNull(model);
        model.Name = (model.Name ?? string.Empty).Trim();
        if (model.Name.Length is 0 or > 120)
        {
            throw new AdminException("Give the dashboard a name (up to 120 characters).");
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var d = await db.Dashboards.FirstOrDefaultAsync(x => x.Id == model.Id, ct) ?? throw new AdminException("That dashboard no longer exists.");
        if (await db.Dashboards.AnyAsync(x => x.Name == model.Name && x.Id != model.Id, ct))
        {
            throw new AdminException($"There's already a dashboard named \"{model.Name}\".");
        }
        d.Name = model.Name;
        d.Description = string.IsNullOrWhiteSpace(model.Description) ? null : model.Description.Trim();
        d.TimeRange = Ranges.Any(r => r.Value == model.TimeRange) ? model.TimeRange : "-24h";
        d.RefreshSeconds = RefreshOptions.Any(r => r.Seconds == model.RefreshSeconds) ? model.RefreshSeconds : 0;
        d.LayoutJson = PanelJson.Serialize(model.Panels);
        d.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Appends a panel below the existing ones (e.g. "Add to dashboard" from a search).</summary>
    public async Task AddPanelAsync(UserAccess caller, Guid dashboardId, DashboardPanel panel, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(panel);
        var model = await GetAsync(caller, dashboardId, ct) ?? throw new AdminException("That dashboard no longer exists.");
        ValidatePanel(panel);
        panel.X = 0;
        panel.Y = model.Panels.Count == 0 ? 0 : model.Panels.Max(p => p.Y + p.H);
        model.Panels.Add(panel);
        await SaveAsync(caller, model, ct);
    }

    public async Task DeleteAsync(UserAccess caller, Guid id, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can use dashboards.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Dashboards.Where(d => d.Id == id).ExecuteDeleteAsync(ct);
    }

    public async Task<Guid> DuplicateAsync(UserAccess caller, Guid id, CancellationToken ct)
    {
        var source = await GetAsync(caller, id, ct) ?? throw new AdminException("That dashboard no longer exists.");
        var existing = (await ListAsync(caller, ct)).Select(d => d.Name).ToHashSet(StringComparer.Ordinal);
        var name = $"{source.Name} (copy)";
        for (var n = 2; existing.Contains(name); n++)
        {
            name = $"{source.Name} (copy {n})";
        }
        return await CreateAsync(caller, name, source.Description, source.Panels.Select(p => p.Clone()), source.TimeRange, ct);
    }

    /// <summary>Creates whichever starter dashboards don't exist yet (by name).</summary>
    public async Task<int> CreateStartersAsync(UserAccess caller, CancellationToken ct)
    {
        var existing = (await ListAsync(caller, ct)).Select(d => d.Name).ToHashSet(StringComparer.Ordinal);
        var created = 0;
        foreach (var starter in StarterDashboards.All.Where(s => !existing.Contains(s.Name)))
        {
            await CreateAsync(caller, starter.Name, starter.Description, starter.Panels(), starter.TimeRange, ct);
            created++;
        }
        return created;
    }

    public void ValidatePanel(DashboardPanel panel)
    {
        ArgumentNullException.ThrowIfNull(panel);
        panel.Title = (panel.Title ?? string.Empty).Trim();
        panel.Query = (panel.Query ?? string.Empty).Trim();
        if (panel.Title.Length is 0 or > 120)
        {
            throw new AdminException("Give the panel a title.");
        }
        if (panel.Query.Length == 0)
        {
            throw new AdminException("Enter the panel's search.");
        }
        try
        {
            parser.Parse(panel.Query);
        }
        catch (QueryParseException ex)
        {
            throw new AdminException(ex.Message);
        }
    }

    /// <summary>Runs one panel's search for the window and tenants, shaped for its visualization.</summary>
    public async Task<PanelResult> RunPanelAsync(UserAccess caller, DashboardPanel panel, DateTimeOffset from, DateTimeOffset to, IReadOnlyList<string> tenants, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can use dashboards.", ct);
        ArgumentNullException.ThrowIfNull(panel);
        var allowed = tenants.Where(caller.Tenants.Contains).ToList();
        var watch = Stopwatch.StartNew();
        var response = await search.RunAsync(panel.Query, from, to, allowed, ct);
        if (response.Result is not { } r)
        {
            return new PanelResult { Error = response.Error ?? "The search failed." };
        }

        PanelResult Done(PanelResult result) => new()
        {
            Error = result.Error, Chart = result.Chart, Value = result.Value, Previous = result.Previous, Spark = result.Spark,
            Columns = result.Columns, Rows = result.Rows, NumericColumns = result.NumericColumns, Empty = result.Empty, Elapsed = watch.Elapsed,
        };

        switch (panel.Kind)
        {
            case PanelKind.TimeLine or PanelKind.TimeArea or PanelKind.TimeBars:
                if (r.Shape != ResultShape.Timechart)
                {
                    return new PanelResult { Error = "Time charts need a search ending in | timechart, e.g. | timechart count() by dataset." };
                }
                var kind = panel.Kind switch { PanelKind.TimeLine => "line", PanelKind.TimeArea => "area", _ => "bars" };
                return Done(new PanelResult { Chart = PanelData.Timechart(r, kind), Empty = r.Rows.Count == 0 });

            case PanelKind.Stat:
            {
                var value = PanelData.Stat(r);
                var span = to - from;
                var previousTask = search.RunAsync(panel.Query, from - span, from, allowed, ct);
                var sparkQuery = PanelData.SparklineQuery(panel.Query, parser);
                var sparkTask = sparkQuery is null ? null : search.RunAsync(sparkQuery, from, to, allowed, ct);
                var previous = await previousTask;
                var spark = sparkTask is null ? null : await sparkTask;
                return Done(new PanelResult
                {
                    Value = value,
                    Previous = previous.Result is { } p ? PanelData.Stat(p) : null,
                    Spark = spark?.Result is { Shape: ResultShape.Timechart } s ? PanelData.Sparkline(s) : null,
                    Empty = value is null,
                });
            }

            case PanelKind.Bars or PanelKind.Pie or PanelKind.Map:
            {
                var items = PanelData.Items(r);
                if (items.Count == 0 && r.Rows.Count > 0)
                {
                    return new PanelResult { Error = "No numbers to plot. End the search with | top or | stats count() by a field." };
                }
                var chart = panel.Kind switch { PanelKind.Pie => PanelData.Pie(items), PanelKind.Map => PanelData.Map(items), _ => PanelData.Bars(items) };
                return Done(new PanelResult { Chart = chart, Empty = items.Count == 0 });
            }

            default:
            {
                var (columns, rows, numeric) = PanelData.Table(r);
                return Done(new PanelResult { Columns = columns, Rows = rows, NumericColumns = numeric, Empty = rows.Count == 0 });
            }
        }
    }

    /// <summary>The window for a relative range ending now.</summary>
    public static (DateTimeOffset From, DateTimeOffset To) Window(string range, DateTimeOffset now) =>
        (SearchService.ParseTime(range, now, now.AddHours(-24)), now);

}
