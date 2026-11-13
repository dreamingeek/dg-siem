using System.Text;
using DreaminGeek.Siem.Web.Backups;
using Npgsql;

namespace DreaminGeek.Siem.Tests;

public sealed class BackupTests
{
    private const string Passphrase = "correct horse battery staple";

    [Fact]
    public void Archive_round_trips_and_is_encrypted()
    {
        var entries = new Dictionary<string, byte[]>
        {
            ["pki/ca.pfx"] = [1, 2, 3, 4],
            ["postgres/Tenants.csv"] = Encoding.UTF8.GetBytes("Id,Slug\n1,secret-tenant-name\n"),
        };
        var file = BackupArchive.Write(entries, Passphrase);

        Assert.Equal("DGSB1"u8.ToArray(), file[..5]);
        Assert.DoesNotContain("secret-tenant-name", Encoding.Latin1.GetString(file), StringComparison.Ordinal);
        Assert.DoesNotContain("postgres/", Encoding.Latin1.GetString(file), StringComparison.Ordinal); // entry names are encrypted too

        var read = BackupArchive.Read(file, Passphrase);
        Assert.Equal(entries.Keys.Order(), read.Keys.Order());
        Assert.Equal(entries["pki/ca.pfx"], read["pki/ca.pfx"]);
        Assert.Equal(entries["postgres/Tenants.csv"], read["postgres/Tenants.csv"]);
    }

    [Fact]
    public void Wrong_passphrase_or_tampering_is_refused()
    {
        var file = BackupArchive.Write(new Dictionary<string, byte[]> { ["a"] = [42] }, Passphrase);

        var wrong = Assert.Throws<BackupException>(() => BackupArchive.Read(file, "correct horse battery stapler"));
        Assert.Contains("Wrong backup passphrase", wrong.Message, StringComparison.Ordinal);

        file[^1] ^= 1;
        Assert.Throws<BackupException>(() => BackupArchive.Read(file, Passphrase));
        Assert.Throws<BackupException>(() => BackupArchive.Read("PK\u0003\u0004 not a backup at all, just some zip"u8.ToArray(), Passphrase));
    }

    [Fact]
    public void Short_or_missing_passphrase_is_refused()
    {
        var entries = new Dictionary<string, byte[]> { ["a"] = [1] };
        Assert.Throws<BackupException>(() => BackupArchive.Write(entries, ""));
        Assert.Throws<BackupException>(() => BackupArchive.Write(entries, "short"));
    }

    [Fact]
    public void Next_run_is_the_next_local_time()
    {
        var zone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
        var settings = new BackupSettings(Time: "03:15");

        // 2026-11-12 02:00 CST (08:00Z): later today.
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 3, 15, 0, TimeSpan.FromHours(-6)),
            BackupService.NextRun(settings, zone, new DateTimeOffset(2026, 11, 12, 8, 0, 0, TimeSpan.Zero)));
        // 04:00 CST: tomorrow.
        Assert.Equal(new DateTimeOffset(2026, 11, 13, 3, 15, 0, TimeSpan.FromHours(-6)),
            BackupService.NextRun(settings, zone, new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero)));
        // 02:30 doesn't exist on 2027-03-14 (spring forward): skip to the next day.
        Assert.Equal(new DateTimeOffset(2027, 3, 15, 2, 30, 0, TimeSpan.FromHours(-5)),
            BackupService.NextRun(new BackupSettings(Time: "02:30"), zone, new DateTimeOffset(2027, 3, 14, 6, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void Pruning_keeps_the_bases_differentials_need()
    {
        var now = new DateTimeOffset(2026, 11, 12, 9, 0, 0, TimeSpan.Zero);
        EventBackup B(int daysAgo, string? baseName = null) =>
            new($"events-{daysAgo}-{(baseName is null ? "full" : "diff")}.zip", baseName is null, baseName, now.AddDays(-daysAgo), 1);
        var backups = new List<EventBackup>
        {
            B(45), B(44, "events-45-full.zip"),                    // old full + diff: both go
            B(35), B(34, "events-35-full.zip"), B(29, "events-35-full.zip"), // 29-day diff keeps the 35-day full; 34 goes
            B(28), B(27, "events-28-full.zip"),
        };

        var kept = BackupService.Retained(backups, now.AddDays(-30)).Select(b => b.Name).Order().ToList();

        Assert.Equal(["events-27-diff.zip", "events-28-full.zip", "events-29-diff.zip", "events-35-full.zip"], kept);
    }

    [Fact]
    public void Pruning_never_removes_the_last_good_backup()
    {
        var now = new DateTimeOffset(2026, 11, 12, 9, 0, 0, TimeSpan.Zero);
        var full = new EventBackup("events-full.zip", true, null, now.AddDays(-90), 1);
        var diff = new EventBackup("events-diff.zip", false, "events-full.zip", now.AddDays(-89), 1);
        var older = new EventBackup("events-older.zip", true, null, now.AddDays(-97), 1);

        var kept = BackupService.Retained([older, full, diff], now.AddDays(-30));

        Assert.Equal([full, diff], kept);
    }

    /// <summary>Against a real PostgreSQL when <c>DGSIEM_TEST_POSTGRES</c> is set (a throwaway database: it's wiped).</summary>
    [Fact]
    public async Task Postgres_export_and_import_round_trip()
    {
        var cs = Environment.GetEnvironmentVariable("DGSIEM_TEST_POSTGRES");
        if (string.IsNullOrEmpty(cs))
        {
            return;
        }
        var ct = CancellationToken.None;
        await using (var db = new NpgsqlConnection(cs))
        {
            await db.OpenAsync(ct);
            await using var cmd = new NpgsqlCommand("""
                DROP TABLE IF EXISTS "Child", "Parent", "__EFMigrationsHistory";
                CREATE TABLE "__EFMigrationsHistory" ("MigrationId" text PRIMARY KEY, "ProductVersion" text NOT NULL);
                INSERT INTO "__EFMigrationsHistory" VALUES ('20260101_Init', '10.0'), ('20260201_More', '10.0');
                CREATE TABLE "Parent" ("Id" serial PRIMARY KEY, "Name" text NOT NULL, "Json" text);
                CREATE TABLE "Child" ("Id" bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, "ParentId" int NOT NULL REFERENCES "Parent"("Id"), "Note" text);
                INSERT INTO "Parent" ("Name", "Json") VALUES ('a, "quoted"', '{"x":[1,2]}'), (E'multi\nline', NULL);
                INSERT INTO "Child" ("ParentId", "Note") VALUES (2, 'first'), (1, NULL);
                """, db);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        var files = await PostgresDump.ExportAsync(cs, ct);
        Assert.Contains("postgres/Parent.csv", files.Keys);

        await using (var db = new NpgsqlConnection(cs))
        {
            await db.OpenAsync(ct);
            await using var cmd = new NpgsqlCommand("""DELETE FROM "Child"; DELETE FROM "Parent"; INSERT INTO "Parent" ("Name") VALUES ('stray');""", db);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        var counts = await PostgresDump.ImportAsync(cs, files, ct);
        Assert.Equal(2, counts["Parent"]);

        await using (var db = new NpgsqlConnection(cs))
        {
            await db.OpenAsync(ct);
            await using var check = new NpgsqlCommand("""SELECT string_agg("Name" || '|' || coalesce("Json", 'null'), ';' ORDER BY "Id") FROM "Parent" """, db);
            Assert.Equal("a, \"quoted\"|{\"x\":[1,2]};multi\nline|null", await check.ExecuteScalarAsync(ct));
            // Sequences continue after the restored rows.
            await using var insert = new NpgsqlCommand("""INSERT INTO "Parent" ("Name") VALUES ('next') RETURNING "Id"; """, db);
            Assert.Equal(3, await insert.ExecuteScalarAsync(ct));
            await using var child = new NpgsqlCommand("""INSERT INTO "Child" ("ParentId") VALUES (1) RETURNING "Id"; """, db);
            Assert.Equal(3L, await child.ExecuteScalarAsync(ct));

            // A different schema version is refused before anything changes.
            await using var migrate = new NpgsqlCommand("""INSERT INTO "__EFMigrationsHistory" VALUES ('20260301_Newer', '10.0')""", db);
            await migrate.ExecuteNonQueryAsync(ct);
        }
        var ex = await Assert.ThrowsAsync<BackupException>(() => PostgresDump.ImportAsync(cs, files, ct));
        Assert.Contains("doesn't match", ex.Message, StringComparison.Ordinal);
    }
}
