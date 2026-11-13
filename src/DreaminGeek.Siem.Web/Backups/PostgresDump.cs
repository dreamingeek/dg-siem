using System.Text;
using Npgsql;

namespace DreaminGeek.Siem.Web.Backups;

/// <summary>
/// Exports and imports every table in the <c>public</c> schema with PostgreSQL's COPY (CSV), so the server
/// can back itself up without pg_dump in its image. Import expects the same schema (the server's own EF migrations,
/// checked against <c>__EFMigrationsHistory</c>) and replaces all rows.
/// </summary>
public static class PostgresDump
{
    private const string HistoryTable = "__EFMigrationsHistory";

    /// <summary>One CSV (with header) per table, keyed <c>postgres/&lt;table&gt;.csv</c>.</summary>
    public static async Task<Dictionary<string, byte[]>> ExportAsync(string connectionString, CancellationToken ct)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        await using var db = new NpgsqlConnection(connectionString);
        await db.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct); // one consistent snapshot
        foreach (var table in await TablesAsync(db, ct))
        {
            using var reader = await db.BeginTextExportAsync($"COPY {Quote(table)} TO STDOUT WITH (FORMAT csv, HEADER true)", ct);
            files[$"postgres/{table}.csv"] = Encoding.UTF8.GetBytes(await reader.ReadToEndAsync(ct));
        }
        await tx.CommitAsync(ct);
        return files;
    }

    /// <summary>
    /// Replaces every table's rows with the backup's. The database must already be migrated to the backup's
    /// schema version (start the server once, or run its migrations, before restoring).
    /// </summary>
    public static async Task<IReadOnlyDictionary<string, int>> ImportAsync(string connectionString, IReadOnlyDictionary<string, byte[]> files, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(files);
        var backupTables = files.Keys.Where(k => k.StartsWith("postgres/", StringComparison.Ordinal) && k.EndsWith(".csv", StringComparison.Ordinal))
            .ToDictionary(k => k["postgres/".Length..^".csv".Length], k => files[k], StringComparer.Ordinal);
        await using var db = new NpgsqlConnection(connectionString);
        await db.OpenAsync(ct);
        var tables = await TablesAsync(db, ct);

        // Same migrations, or the columns won't line up.
        if (backupTables.TryGetValue(HistoryTable, out var history))
        {
            var theirs = MigrationIds(history);
            var ours = new List<string>();
            await using (var cmd = new NpgsqlCommand($"SELECT \"MigrationId\" FROM {Quote(HistoryTable)} ORDER BY 1", db))
            await using (var r = await cmd.ExecuteReaderAsync(ct))
            {
                while (await r.ReadAsync(ct))
                {
                    ours.Add(r.GetString(0));
                }
            }
            ours.Sort(StringComparer.Ordinal);
            if (!theirs.SequenceEqual(ours))
            {
                throw new BackupException(
                    $"The backup's database schema ({theirs.LastOrDefault() ?? "none"}) doesn't match this server's ({ours.LastOrDefault() ?? "none"}). " +
                    "Restore with the same DG SIEM version the backup was made with.");
            }
        }

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        await using var tx = await db.BeginTransactionAsync(ct);
        await Execute(db, $"TRUNCATE {string.Join(", ", tables.Where(t => t != HistoryTable).Select(Quote))} CASCADE", ct);
        // Referenced tables first, so foreign keys hold as each table goes in (no superuser needed).
        foreach (var table in await ParentsFirstAsync(db, tables, ct))
        {
            if (table == HistoryTable || !backupTables.ContainsKey(table))
            {
                continue;
            }
            var csv = Encoding.UTF8.GetString(backupTables[table]);
            var header = csv.Split('\n', 2)[0].TrimEnd('\r');
            if (header.Length == 0)
            {
                continue;
            }
            // Column names are mixed case (TenantId): quote each one.
            var columns = string.Join(", ", header.Split(',').Select(c => Quote(c.Trim().Trim('"'))));
            await using (var writer = await db.BeginTextImportAsync($"COPY {Quote(table)} ({columns}) FROM STDIN WITH (FORMAT csv, HEADER true)", ct))
            {
                await writer.WriteAsync(csv);
            }
            await using var count = new NpgsqlCommand($"SELECT count(*) FROM {Quote(table)}", db);
            counts[table] = Convert.ToInt32(await count.ExecuteScalarAsync(ct), System.Globalization.CultureInfo.InvariantCulture);
        }
        await ResetSequencesAsync(db, ct);
        await tx.CommitAsync(ct);
        return counts;
    }

    /// <summary><paramref name="tables"/> ordered so every table comes after the tables its foreign keys point at.</summary>
    private static async Task<List<string>> ParentsFirstAsync(NpgsqlConnection db, List<string> tables, CancellationToken ct)
    {
        var parents = tables.ToDictionary(t => t, _ => new HashSet<string>(StringComparer.Ordinal), StringComparer.Ordinal);
        await using (var cmd = new NpgsqlCommand(
            "SELECT c.relname, p.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class p ON p.oid = k.confrelid " +
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE k.contype = 'f' AND n.nspname = 'public'", db))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            while (await r.ReadAsync(ct))
            {
                var (child, parent) = (r.GetString(0), r.GetString(1));
                if (child != parent && parents.TryGetValue(child, out var set) && parents.ContainsKey(parent))
                {
                    set.Add(parent);
                }
            }
        }
        var ordered = new List<string>();
        var done = new HashSet<string>(StringComparer.Ordinal);
        while (ordered.Count < tables.Count)
        {
            var ready = tables.Where(t => !done.Contains(t) && parents[t].All(done.Contains)).ToList();
            if (ready.Count == 0)
            {
                throw new BackupException($"Can't order tables with circular foreign keys: {string.Join(", ", tables.Where(t => !done.Contains(t)))}.");
            }
            ordered.AddRange(ready);
            done.UnionWith(ready);
        }
        return ordered;
    }

    private static async Task<List<string>> TablesAsync(NpgsqlConnection db, CancellationToken ct)
    {
        var tables = new List<string>();
        await using var cmd = new NpgsqlCommand(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name", db);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            tables.Add(r.GetString(0));
        }
        return tables;
    }

    /// <summary>Identity/serial columns continue after the restored rows' highest id.</summary>
    private static async Task ResetSequencesAsync(NpgsqlConnection db, CancellationToken ct)
    {
        var columns = new List<(string Table, string Column)>();
        await using (var cmd = new NpgsqlCommand(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' AND (is_identity = 'YES' OR column_default LIKE 'nextval(%')", db))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            while (await r.ReadAsync(ct))
            {
                columns.Add((r.GetString(0), r.GetString(1)));
            }
        }
        foreach (var (table, column) in columns)
        {
            await Execute(db,
                $"SELECT setval(pg_get_serial_sequence('{Quote(table).Replace("'", "''", StringComparison.Ordinal)}', '{column.Replace("'", "''", StringComparison.Ordinal)}'), " +
                $"COALESCE((SELECT MAX({Quote(column)}) FROM {Quote(table)}), 0) + 1, false)", ct);
        }
    }

    private static List<string> MigrationIds(byte[] csv) =>
        Encoding.UTF8.GetString(csv).Split('\n').Skip(1).Select(l => l.Split(',')[0].Trim('"', '\r')).Where(l => l.Length > 0).Order(StringComparer.Ordinal).ToList();

    private static async Task Execute(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(sql, db);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string Quote(string identifier) => "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
}
