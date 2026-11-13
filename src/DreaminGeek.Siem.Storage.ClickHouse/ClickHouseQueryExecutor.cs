using System.Diagnostics;
using ClickHouse.Driver;
using ClickHouse.Driver.ADO.Parameters;
using DreaminGeek.Siem.Query;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

/// <summary>Search could not run (for example, row-policy protection isn't available).</summary>
public sealed class SearchUnavailableException(string message) : Exception(message);

/// <summary>
/// Runs compiled searches read-only with a time limit, as the row-policy reader with only the
/// query's tenant roles active (see <see cref="TenantRowPolicies"/>).
/// </summary>
public sealed class ClickHouseQueryExecutor(ClickHouseClient admin, TenantRowPolicies policies, IOptions<ClickHouseOptions> options) : IQueryExecutor
{
    public static readonly TimeSpan MaxExecutionTime = TimeSpan.FromSeconds(60);

    public async Task<QueryResult> ExecuteAsync(CompiledQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var parameters = new ClickHouseParameterCollection();
        foreach (var (name, value) in query.Parameters)
        {
            parameters.Add(new ClickHouseDbParameter { ParameterName = name, Value = value, ClickHouseType = query.ParameterTypes[name] });
        }

        ClickHouseClient client;
        IReadOnlyList<string>? roles = null;
        if (options.Value.EnforceRowPolicies)
        {
            if (!policies.Ready)
            {
                throw new SearchUnavailableException(policies.Problem ?? "Row-policy protection is not available.");
            }
            if (query.TenantIds.Count == 0 || query.TenantIds.Any(t => !TenantRowPolicies.IsValidSlug(t)))
            {
                throw new SearchUnavailableException("This search has no valid tenant scope.");
            }
            await policies.SyncTenantsAsync(query.TenantIds, cancellationToken); // a tenant added since startup
            client = policies.Reader;
            roles = query.TenantIds.Select(TenantRowPolicies.RoleName).ToList();
        }
        else
        {
            client = admin;
        }

        var queryOptions = new QueryOptions
        {
            Roles = roles,
            MaxExecutionTime = MaxExecutionTime,
            CustomSettings = new Dictionary<string, object>
            {
                ["readonly"] = 2,                        // no writes or DDL, whatever the SQL says
                ["prefer_column_name_to_alias"] = 1,     // `message` in WHERE is the column, never an output alias
                ["max_result_rows"] = query.RowLimit + 1,
                ["result_overflow_mode"] = "break",
            },
        };

        var stopwatch = Stopwatch.StartNew();
        var rows = new List<object?[]>();
        using (var reader = await client.ExecuteReaderAsync(query.Sql, parameters, queryOptions, cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var row = new object?[reader.FieldCount];
                for (var i = 0; i < row.Length; i++)
                {
                    var value = reader.GetValue(i);
                    row[i] = value is DBNull ? null : value;
                }
                rows.Add(row);
            }
        }
        stopwatch.Stop();
        return new QueryResult(query.Columns, rows, query.Shape, rows.Count >= query.RowLimit, stopwatch.Elapsed);
    }
}
