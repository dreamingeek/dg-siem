using System.Data.Common;
using System.Text.RegularExpressions;
using ClickHouse.Driver;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

/// <summary>
/// Second tenant-isolation layer, enforced by ClickHouse itself:
/// <list type="bullet">
/// <item>a read-only reader user that searches run as, with a base row policy of "no rows";</item>
/// <item>one role per tenant (<c>dgsiem_t_&lt;slug&gt;</c>) whose row policy allows only that tenant's rows;</item>
/// <item>the roles are granted to the reader but never active by default: each search activates
/// only the caller's tenant roles. Policies are permissive (OR'ed), so the reader sees exactly
/// the union of its active tenants, and nothing at all with no roles.</item>
/// </list>
/// If setup or the self-test fails, <see cref="Ready"/> stays false and searches are refused.
/// </summary>
public sealed partial class TenantRowPolicies : IDisposable
{
    private static readonly Regex SlugPattern = SlugRegex();

    private readonly ClickHouseClient _admin;
    private readonly ClickHouseOptions _options;
    private readonly ILogger<TenantRowPolicies> _logger;
    private readonly HashSet<string> _synced = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _adminUser;
    private readonly string _password;

    public TenantRowPolicies(ClickHouseClient admin, IOptions<ClickHouseOptions> options, ILogger<TenantRowPolicies> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _admin = admin;
        _options = options.Value;
        _logger = logger;

        var builder = new DbConnectionStringBuilder { ConnectionString = _options.ConnectionString };
        _adminUser = Get(builder, "Username") ?? Get(builder, "User") ?? "default";
        _password = Get(builder, "Password") ?? string.Empty;
        builder.Remove("User");
        builder["Username"] = _options.ReaderUsername;
        Reader = new ClickHouseClient(builder.ConnectionString);
    }

    /// <summary>Client for searches. Only usable with tenant roles when <see cref="Ready"/>.</summary>
    public ClickHouseClient Reader { get; }

    /// <summary>True once the reader, base policy and self-test all succeeded.</summary>
    public bool Ready { get; private set; }

    /// <summary>Why <see cref="Ready"/> is false, for the search error message.</summary>
    public string? Problem { get; private set; } = "Row-policy setup hasn't run yet.";

    public static string RoleName(string tenantSlug) => "dgsiem_t_" + tenantSlug.Replace('-', '_');

    public static bool IsValidSlug(string slug) => SlugPattern.IsMatch(slug);

    /// <summary>Creates/updates the reader and base policy, syncs tenant roles, then self-tests.</summary>
    public async Task InitializeAsync(IEnumerable<string> tenantSlugs, CancellationToken ct)
    {
        try
        {
            var db = Ident(_options.Database);
            var reader = Ident(_options.ReaderUsername);
            var password = Literal(_password);
            await ExecAsync($"CREATE USER IF NOT EXISTS {reader} IDENTIFIED WITH sha256_password BY {password} SETTINGS readonly = 2", ct);
            await ExecAsync($"ALTER USER {reader} IDENTIFIED WITH sha256_password BY {password} SETTINGS readonly = 2", ct);
            await ExecAsync($"GRANT SELECT ON {db}.events TO {reader}", ct);
            // Base policy: by itself the reader sees nothing. Tenant roles add rows (policies are OR'ed).
            await ExecAsync($"CREATE ROW POLICY OR REPLACE dgsiem_reader_none ON {db}.events FOR SELECT USING 0 TO {reader}", ct);
            // Keep the main user unrestricted (older ClickHouse hides rows from users with no policy
            // once any policy exists). Best effort: some setups can't attach policies to XML-defined users.
            try
            {
                await ExecAsync($"CREATE ROW POLICY OR REPLACE dgsiem_writer_all ON {db}.events FOR SELECT USING 1 TO {Ident(_adminUser)}", ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogWriterPolicySkipped(_logger, ex.Message.Split('\n')[0]);
            }

            await SyncTenantsAsync(tenantSlugs, ct);
            await SelfTestAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Fail($"ClickHouse row-policy setup failed: {ex.Message.Split('\n')[0]}", ex);
        }
    }

    /// <summary>Ensures a role + row policy exists for every tenant. Cheap to call repeatedly.</summary>
    public async Task SyncTenantsAsync(IEnumerable<string> tenantSlugs, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(tenantSlugs);
        await _gate.WaitAsync(ct);
        try
        {
            var db = Ident(_options.Database);
            var reader = Ident(_options.ReaderUsername);
            foreach (var slug in tenantSlugs.Where(s => !_synced.Contains(s)))
            {
                if (!IsValidSlug(slug))
                {
                    LogBadSlug(_logger, slug);
                    continue;
                }
                var role = Ident(RoleName(slug));
                await ExecAsync($"CREATE ROLE IF NOT EXISTS {role}", ct);
                await ExecAsync($"CREATE ROW POLICY OR REPLACE {Ident("dgsiem_tenant_" + slug.Replace('-', '_'))} ON {db}.events FOR SELECT USING tenant_id = {Literal(slug)} TO {role}", ct);
                await ExecAsync($"GRANT {role} TO {reader}", ct);
                _synced.Add(slug);
            }
            // Granted roles become default roles; tenant roles must only ever be activated per query.
            await ExecAsync($"SET DEFAULT ROLE NONE TO {reader}", ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The reader with no roles must see zero rows. Proves the policies are actually enforced.</summary>
    private async Task SelfTestAsync(CancellationToken ct)
    {
        var table = $"{Ident(_options.Database)}.events";
        var total = Convert.ToInt64(await _admin.ExecuteScalarAsync($"SELECT count() FROM {table}", cancellationToken: ct), System.Globalization.CultureInfo.InvariantCulture);
        var visible = Convert.ToInt64(await Reader.ExecuteScalarAsync($"SELECT count() FROM {table}", cancellationToken: ct), System.Globalization.CultureInfo.InvariantCulture);
        if (visible != 0)
        {
            Fail($"Row-policy self-test failed: the reader saw {visible} of {total} rows with no tenant roles active.", null);
            return;
        }
        Ready = true;
        Problem = null;
        LogReady(_logger, total);
    }

    private void Fail(string problem, Exception? ex)
    {
        Ready = false;
        Problem = problem + " Search is disabled until this is fixed (see the server log), or set ClickHouse:EnforceRowPolicies=false to rely on the query compiler alone.";
        LogFailed(_logger, ex, problem);
    }

    private Task<int> ExecAsync(string sql, CancellationToken ct) => _admin.ExecuteNonQueryAsync(sql, cancellationToken: ct);

    /// <summary>Backtick-quoted identifier (DDL can't take query parameters).</summary>
    private static string Ident(string name) =>
        name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? $"`{name}`" : throw new ArgumentException($"Unsafe ClickHouse identifier '{name}'.", nameof(name));

    /// <summary>Single-quoted string literal with ClickHouse escaping.</summary>
    private static string Literal(string value) => "'" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal) + "'";

    private static string? Get(DbConnectionStringBuilder builder, string key) =>
        builder.TryGetValue(key, out var value) ? value?.ToString() : null;

    public void Dispose()
    {
        Reader.Dispose();
        _gate.Dispose();
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,31}$")]
    private static partial Regex SlugRegex();

    [LoggerMessage(Level = LogLevel.Information, Message = "ClickHouse row policies active and verified ({Total} events hidden from the reader without tenant roles)")]
    private static partial void LogReady(ILogger logger, long total);

    [LoggerMessage(Level = LogLevel.Critical, Message = "{Problem}")]
    private static partial void LogFailed(ILogger logger, Exception? ex, string problem);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not add the main user's allow-all row policy ({Error}); not needed on current ClickHouse versions")]
    private static partial void LogWriterPolicySkipped(ILogger logger, string error);

    [LoggerMessage(Level = LogLevel.Error, Message = "Tenant slug '{Slug}' is not a valid ClickHouse role name; its events can't be searched")]
    private static partial void LogBadSlug(ILogger logger, string slug);
}
