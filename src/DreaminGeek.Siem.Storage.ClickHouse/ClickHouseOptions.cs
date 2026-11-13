namespace DreaminGeek.Siem.Storage.ClickHouse;

public sealed class ClickHouseOptions
{
    public const string SectionName = "ClickHouse";

    /// <summary>HTTP connection string, e.g. <c>Host=clickhouse;Port=8123;Username=dgsiem;Password=...;Database=dgsiem</c>.</summary>
    public string ConnectionString { get; set; } = "Host=localhost;Port=8123;Username=default;Database=dgsiem";

    public string Database { get; set; } = "dgsiem";

    /// <summary>Run embedded migrations at startup.</summary>
    public bool ApplyMigrations { get; set; } = true;

    /// <summary>
    /// Searches run as this read-only ClickHouse user with per-tenant row-policy roles. Created and
    /// kept in sync by the server (the main user needs access management, which the Docker image's
    /// CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 provides). It uses the main user's password.
    /// </summary>
    public string ReaderUsername { get; set; } = "dgsiem_reader";

    /// <summary>
    /// Enforce ClickHouse row policies as a second tenant-isolation layer. When true and setup or
    /// the self-test fails, search is disabled rather than run unprotected. Only turn this off if your
    /// ClickHouse can't do access management; isolation then relies on the query compiler alone.
    /// </summary>
    public bool EnforceRowPolicies { get; set; } = true;

    /// <summary>
    /// Where the server writes ClickHouse config it manages (the cold-tier bucket), as the server sees it.
    /// docker-compose.yml shares this folder with ClickHouse as <c>/etc/clickhouse-server/conf.d</c>.
    /// </summary>
    public string ConfigDirectory { get; set; } = "/var/lib/dg-siem-clickhouse";

    /// <summary>ClickHouse's data folder as ClickHouse sees it (for the cold disk's metadata and cache paths).</summary>
    public string DataPath { get; set; } = "/var/lib/clickhouse/";
}
