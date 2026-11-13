using System.Reflection;
using ClickHouse.Driver;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

/// <summary>Applies the embedded <c>Migrations/*.sql</c> files in order, once each.</summary>
public sealed partial class ClickHouseMigrator(ClickHouseClient client, IOptions<ClickHouseOptions> options, ILogger<ClickHouseMigrator> logger)
{
    private readonly string _db = options.Value.Database;

    public async Task MigrateAsync(CancellationToken cancellationToken)
    {
        await ExecAsync($"CREATE DATABASE IF NOT EXISTS {_db}", cancellationToken);
        await ExecAsync(
            $"CREATE TABLE IF NOT EXISTS {_db}.schema_migrations (name String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY name",
            cancellationToken);

        var applied = new HashSet<string>(StringComparer.Ordinal);
        using (var reader = await client.ExecuteReaderAsync($"SELECT name FROM {_db}.schema_migrations", cancellationToken: cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                applied.Add(reader.GetString(0));
            }
        }

        var assembly = typeof(ClickHouseMigrator).Assembly;
        foreach (var resource in assembly.GetManifestResourceNames().Where(n => n.EndsWith(".sql", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            var name = resource[(resource.IndexOf(".Migrations.", StringComparison.Ordinal) + ".Migrations.".Length)..];
            if (applied.Contains(name))
            {
                continue;
            }

            LogApplying(logger, name);
            var sql = (await ReadResourceAsync(assembly, resource)).Replace("{db}", _db, StringComparison.Ordinal);
            foreach (var statement in SplitStatements(sql))
            {
                await ExecAsync(statement, cancellationToken);
            }
            await ExecAsync($"INSERT INTO {_db}.schema_migrations (name) VALUES ('{name.Replace("'", "", StringComparison.Ordinal)}')", cancellationToken);
        }
    }

    private Task<int> ExecAsync(string sql, CancellationToken ct) =>
        client.ExecuteNonQueryAsync(sql, cancellationToken: ct);

    private static async Task<string> ReadResourceAsync(Assembly assembly, string resource)
    {
        await using var stream = assembly.GetManifestResourceStream(resource)!;
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

    /// <summary>Splits on ';' at end of line and drops comment-only chunks.</summary>
    internal static IEnumerable<string> SplitStatements(string sql) =>
        sql.Split(";\n", StringSplitOptions.TrimEntries)
           .Select(s => string.Join('\n', s.Split('\n').Where(l => !l.TrimStart().StartsWith("--", StringComparison.Ordinal))).Trim().TrimEnd(';'))
           .Where(s => s.Length > 0);

    [LoggerMessage(Level = LogLevel.Information, Message = "Applying ClickHouse migration {Migration}")]
    private static partial void LogApplying(ILogger logger, string migration);
}
