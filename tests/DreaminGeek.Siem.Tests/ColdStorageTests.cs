using System.Xml.Linq;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web.Admin;
using DreaminGeek.Siem.Web.Storage;

namespace DreaminGeek.Siem.Tests;

public sealed class ColdStorageTests
{
    [Fact]
    public void Config_matches_the_original_compose_file_so_existing_cold_data_carries_on()
    {
        var generated = XDocument.Parse(ClickHouseStorage.ColdStorageConfig(
            new ColdBucket("https://s3.us-west-004.backblazeb2.com/b/dg-siem/", "key<&>", "se\"cr'et&<x>"), "/var/lib/clickhouse"));
        var legacy = XDocument.Load(Path.Combine(RepoRoot(), "deploy", "clickhouse", "storage-s3.xml"));

        // Same disks, policy and volumes, and the same metadata/cache paths.
        static IEnumerable<string> Shape(XDocument d) => d.Descendants()
            .Where(e => e.Name.LocalName is "metadata_path" or "path" or "disk" or "type" or "max_size" or "move_factor" or "support_batch_delete")
            .Select(e => $"{string.Join('/', e.AncestorsAndSelf().Reverse().Select(a => a.Name.LocalName))}={e.Value}");
        Assert.Equal(Shape(legacy).Order(), Shape(generated).Order());

        // Values are escaped, not spliced into the XML.
        var disk = generated.Descendants(ClickHouseStorage.ColdDisk).Single();
        Assert.Equal("key<&>", disk.Element("access_key_id")!.Value);
        Assert.Equal("se\"cr'et&<x>", disk.Element("secret_access_key")!.Value);
        Assert.Equal("true", disk.Element("skip_access_check")!.Value);
    }

    [Theory]
    [InlineData("https://s3.us-west-004.backblazeb2.com/my-bucket/dg-siem/", "https://s3.us-west-004.backblazeb2.com/my-bucket/dg-siem/")]
    [InlineData("  https://s3.us-east-1.wasabisys.com/my-bucket/dg-siem  ", "https://s3.us-east-1.wasabisys.com/my-bucket/dg-siem/")]
    [InlineData("http://minio.lan:9000/siem/", "http://minio.lan:9000/siem/")]
    [InlineData("https://my-bucket.s3.us-east-2.amazonaws.com/", "https://my-bucket.s3.us-east-2.amazonaws.com/")]
    public void Bucket_urls_are_normalized(string input, string expected) =>
        Assert.Equal(expected, ColdStorageService.NormalizeEndpoint(input));

    [Theory]
    [InlineData("")]
    [InlineData("s3.us-west-004.backblazeb2.com/my-bucket/")]
    [InlineData("ftp://host/bucket/")]
    [InlineData("https://s3.us-west-004.backblazeb2.com/")]
    [InlineData("https://host/bucket/?x=1")]
    public void Bad_bucket_urls_are_refused(string input) =>
        Assert.Throws<AdminException>(() => ColdStorageService.NormalizeEndpoint(input));

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "DreaminGeek.Siem.slnx")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("Repo root not found.");
    }
}
